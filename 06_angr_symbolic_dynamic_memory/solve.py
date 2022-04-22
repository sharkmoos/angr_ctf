import angr
import claripy
import sys

class passwordObject:
    def __init__(self, bitvector, mallocPointer, fakeAddr):
        self.bitvector = bitvector
        self.mallocPointer = mallocPointer
        self.fakeAddr = fakeAddr

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048699
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s").
  # (!)


  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  password0 = passwordObject(claripy.BVS('password0', 64), 0xabcc8a4, 0x804b0c0) # we can just use bss segment as well for the data
  password1 = passwordObject(claripy.BVS('password1', 64), 0xabcc8ac, 0x804b0c8) # the pointers will be overwritten 

  # overwrite the pointer to the heap with a pointer to where angr will put the password attempt
  initial_state.memory.store(password0.mallocPointer, password0.fakeAddr, endness=project.arch.memory_endness)
  initial_state.memory.store(password1.mallocPointer, password1.fakeAddr, endness=project.arch.memory_endness)

  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(password0.fakeAddr, password0.bitvector)
  initial_state.memory.store(password1.fakeAddr, password1.bitvector)

  simulation = project.factory.simgr(initial_state)


  def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(sys.stdout.fileno())

    # Return whether 'Good Job.' has been printed yet.
    # (!)
    if b"Good Job" in stdout_output:
        found = True
    else:
        found = False
    return found  # :boolean

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b"Try again" in stdout_output:
        abort = True
    else:
        abort = False
    return abort # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solutions = [
        solution_state.solver.eval(password0.bitvector,cast_to=bytes).decode(),
        solution_state.solver.eval(password1.bitvector,cast_to=bytes).decode()
    ]

    solution = " ".join(x for x in solutions)

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
