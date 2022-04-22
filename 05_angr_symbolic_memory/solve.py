import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)


  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)

  #    __isoc99_scanf(format: "%8s %8s %8s %8s", 0xa1ba1c0, 0xa1ba1c8, 0xa1ba1d0, 0xa1ba1d8)
  passwords = [
      [claripy.BVS('password0', 64), 0xa1ba1c0],
      [claripy.BVS('password1', 64), 0xa1ba1c8],
      [claripy.BVS('password2', 64), 0xa1ba1d0],
      [claripy.BVS('password3', 64), 0xa1ba1d8],
  ]

  initial_state.memory.store(passwords[0][1], passwords[0][0])
  initial_state.memory.store(passwords[1][1], passwords[1][0])
  initial_state.memory.store(passwords[2][1], passwords[2][0])
  initial_state.memory.store(passwords[3][1], passwords[3][0])
  

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

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=bytes
    # which returns bytes that can be decoded to a string instead of an integer.
    # (!)
    solutions = [
        solution_state.solver.eval(passwords[0][0],cast_to=bytes).decode(),
        solution_state.solver.eval(passwords[1][0],cast_to=bytes).decode(),
        solution_state.solver.eval(passwords[2][0],cast_to=bytes).decode(),
        solution_state.solver.eval(passwords[3][0],cast_to=bytes).decode()
    ]
    solution = " ".join([x for x in solutions])

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
