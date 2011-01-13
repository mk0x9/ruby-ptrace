#ifdef __i386__
#include "ptrace_linux_x86.c"
#endif
#ifdef __x86_64__
#include "ptrace_linux_x86_64.c"
#endif  

#ifdef PT_SYSCALL
static VALUE
ptrace_syscall(int argc, VALUE *argv, VALUE self)
{
    VALUE data = INT2FIX(0);
    if (argc == 1) {
	data = argv[0];
    }
    return ptrace_continue(self, PT_SYSCALL, data);
}
#else
UNSUPPORTED_API(ptrace_syscall, int argc, VALUE *argv, VALUE self)
#endif


static VALUE
ptrace_alloc(VALUE mod, pid_t pid)
{
    VALUE v = rb_obj_alloc(mod);
    rb_ivar_set(v, id_ptrace_pid, LONG2NUM(pid));
    return v;
}

#ifdef WSTOPSIG
static VALUE
ptrace_wait(VALUE self)
{
    pid_t pid = get_pid(self);
    int st;
    int ret = rb_waitpid(pid, &st, 0);
    fprintf(stderr, "waitpided\n");
#ifdef DEBUG
    fprintf(stderr, "%s: pid: %d\n", __func__, pid);
#endif
    
    if (ret == -1) {
	rb_sys_fail("waitpid(2)");
    }

    if (WIFSTOPPED(st)) {
	return si_signo_symbol(WSTOPSIG(st));
    }
    return Qnil;
}

#else
UNSUPPORTED_API(ptracw_wait, VALUE self)
#endif
