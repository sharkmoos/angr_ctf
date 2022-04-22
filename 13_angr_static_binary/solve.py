# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.
import angr
import claripy
import sys

def main(argv):
    elf = argv[1]
    project = angr.Project(elf)
    main_addr = 0x80488fe
    initial_state = project.factory.blank_state(
        addr = main_addr,
        add_options = {
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    sim = project.factory.simgr(initial_state, veritesting=True)

    project.hook_symbol("_IO_printf", angr.SIM_PROCEDURES['libc']['printf']())    
    project.hook_symbol("__isoc99_scanf", angr.SIM_PROCEDURES['libc']['scanf']())    
    project.hook_symbol("_IO_puts", angr.SIM_PROCEDURES['libc']['puts']())    

    def is_successful(state):   return b"Good Job" in state.posix.dumps(sys.stdout.fileno())
    def should_abort(state):    return b"Try again" in state.posix.dumps(sys.stdout.fileno())

    sim.explore(find=is_successful, avoid=should_abort)
    
    if sim.found:
        solution_state = sim.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()).decode())

if __name__ == "__main__":
    main(sys.argv)