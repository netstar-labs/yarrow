package scan

// Match is one occurrence of a pattern: the half-open byte range [Start, End).
type Match struct{ Start, End int }

// Matcher is the common interface of every compiled pattern — an NFA program
// (literal, hex, regexp) or a Text (a modified string). pkg/compile holds patterns
// as Matchers regardless of kind.
type Matcher interface {
	FindAll(input []byte) []Match
	Match(input []byte) bool
}

// vmState is reusable scratch for the Pike VM. Reusing it across every start of a
// FindAll makes a whole scan allocate O(1) instead of the O(len) thread-list and
// visited-set allocations a naive per-start/per-step simulation would do. seen is
// a generation-stamped visited set (seen[pc] == gen ⇔ pc already added this
// closure), so it is never cleared — gen is just bumped.
type vmState struct {
	seen       []int
	gen        int
	bufA, bufB []int
}

func newVMState(nInst int) *vmState {
	return &vmState{
		seen: make([]int, nInst),
		bufA: make([]int, 0, nInst),
		bufB: make([]int, 0, nInst),
	}
}

// FindAll returns every occurrence of the program in input, including overlapping
// ones — YARA reports each match position, and the condition layer decides how to
// count or filter them. Matches are ordered by start, then by end.
//
// It restarts the NFA at each position (O(len·states) per start); a required-atom
// prefilter that narrows the start positions is the planned performance phase.
// Buffer reuse (vmState) keeps the per-scan allocation flat regardless.
func (p program) FindAll(input []byte) []Match {
	if len(p) == 0 {
		return nil
	}
	vm := newVMState(len(p))
	var out []Match
	for start := 0; start <= len(input); start++ {
		p.matchesFrom(input, start, vm, &out)
	}
	return out
}

// Match reports whether the program matches anywhere in input.
func (p program) Match(input []byte) bool {
	if len(p) == 0 {
		return false
	}
	vm := newVMState(len(p))
	var out []Match
	for start := 0; start <= len(input); start++ {
		p.matchesFrom(input, start, vm, &out)
		if len(out) > 0 {
			return true
		}
	}
	return false
}

// matchesFrom simulates the NFA anchored at start and appends every (start, end)
// where a thread reaches opMatch. Threads are deduplicated by pc each step (via
// the generation-stamped visited set), so an unbounded jump loop terminates. cur
// and next alternate between vm's two buffers, so no per-step slice is allocated.
func (p program) matchesFrom(input []byte, start int, vm *vmState, out *[]Match) {
	n := len(input)
	vm.gen++
	vm.bufA = p.addThread(vm.bufA[:0], vm, 0, start, n)
	cur, next := &vm.bufA, &vm.bufB

	for pos := start; ; pos++ {
		for _, pc := range *cur {
			if p[pc].op == opMatch {
				*out = append(*out, Match{Start: start, End: pos})
			}
		}
		if pos >= n {
			return
		}
		b := input[pos]
		vm.gen++
		*next = (*next)[:0]
		for _, pc := range *cur {
			if p[pc].op == opClass && p[pc].set.has(b) {
				*next = p.addThread(*next, vm, pc+1, pos+1, n)
			}
		}
		cur, next = next, cur
		if len(*cur) == 0 {
			return
		}
	}
}

// addThread adds pc to list, following epsilon transitions (opJmp/opSplit and the
// position assertions, evaluated against the absolute position pos in an input of
// length n) and recording only the consuming (opClass) and accepting (opMatch)
// states. The generation-stamped visited set dedups threads and makes epsilon
// loops terminate. It returns the (possibly grown) list.
func (p program) addThread(list []int, vm *vmState, pc, pos, n int) []int {
	if vm.seen[pc] == vm.gen {
		return list
	}
	vm.seen[pc] = vm.gen
	switch p[pc].op {
	case opJmp:
		return p.addThread(list, vm, p[pc].x, pos, n)
	case opSplit:
		list = p.addThread(list, vm, p[pc].x, pos, n)
		return p.addThread(list, vm, p[pc].y, pos, n)
	case opAssertStart:
		if pos == 0 {
			return p.addThread(list, vm, pc+1, pos, n)
		}
		return list
	case opAssertEnd:
		if pos == n {
			return p.addThread(list, vm, pc+1, pos, n)
		}
		return list
	default: // opClass, opMatch
		return append(list, pc)
	}
}
