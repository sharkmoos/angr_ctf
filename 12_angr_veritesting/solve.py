# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )
  simulation = project.factory.simgr(initial_state, veritesting=True)


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

    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())

if __name__ == '__main__':
  main(sys.argv)