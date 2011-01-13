#include <mach/thread_status.h>
#include <mach/mach.h>

static VALUE
ptrace_getregs(VALUE self)
{
    x86_thread_state_t thread_state;
    VALUE ret = Qnil;
    int state_count = x86_THREAD_STATE_COUNT; /* only x86 supported */
    kern_return_t thread_status = thread_get_status(pthread_self(),
                                                    x86_THREAD_STATE,
                                                    &thread_state,
                                                    &state_count);
    if ( thread_status != 0 )
    {
        rb_raise(rb_ePTraceError, "thread_get_state failed with error code: %d",
                 thread_status);
    }

    ret = rb_struct_new(rb_sPTraceRegStruct,
                        ULONG2NUM(thread_state.uts.ts64.__rax),
                        ULONG2NUM(thread_state.uts.ts64.__rbx),
                        ULONG2NUM(thread_state.uts.ts64.__rcx),
                        ULONG2NUM(thread_state.uts.ts64.__rdi),
                        ULONG2NUM(thread_state.uts.ts64.__rsi),
                        ULONG2NUM(thread_state.uts.ts64.__rbp),
                        ULONG2NUM(thread_state.uts.ts64.__rsp),
                        ULONG2NUM(thread_state.uts.ts64.__r8), 
                        ULONG2NUM(thread_state.uts.ts64.__r9),
                        ULONG2NUM(thread_state.uts.ts64.__r10),
                        ULONG2NUM(thread_state.uts.ts64.__r11),
                        ULONG2NUM(thread_state.uts.ts64.__r12),
                        ULONG2NUM(thread_state.uts.ts64.__r13),
                        ULONG2NUM(thread_state.uts.ts64.__r14),
                        ULONG2NUM(thread_state.uts.ts64.__r15),
                        ULONG2NUM(thread_state.uts.ts64.__rip),
                        ULONG2NUM(thread_state.uts.ts64.__rflags),
                        ULONG2NUM(thread_state.uts.ts64.__cs),
                        ULONG2NUM(thread_state.uts.ts64.__fs),
                        ULONG2NUM(thread_state.uts.ts64.__gs));
                        
    return ret;
}

static VALUE
ptrace_setregs(VALUE self, VALUE data)
{
    x86_thread_state_t current_thread_state;
    VALUE ret = Qnil;
    int state_count = x86_THREAD_STATE_COUNT; /* only x86 supported */
    kern_return_t thread_status = thread_get_status(pthread_self(),
                                                    x86_THREAD_STATE,
                                                    &current_thread_state,
                                                    &state_count);
    if ( thread_status != 0 )
    {
        rb_raise(rb_ePTraceError, "thread_get_state failed with error code: %d",
                 thread_status);
    }
    
#define SET(reg) {VALUE v = rb_struct_getmember(data, rb_intern(#reg)); \
        current_thread_state.uts.ts64.__##reg = NUM2ULONG(v);}
    SET(rax);
    SET(rbx);
    SET(rcx);
    SET(rdi);
    SET(rsi);
    SET(rbp);
    SET(rsp);
    SET(r8);
    SET(r9);
    SET(r10);
    SET(r11);
    SET(r12);
    SET(r13);
    SET(r14);
    SET(r15);
    SET(rip);
    SET(rflags);
    SET(cs);
    SET(fs);
    SET(gs);
    kern_return_t set_thread_status = thread_set_state(pthread_self(),
                                                       x86_DEBUG_STATE,
                                                       &current_thread_state,
                                                       x86_DEBUG_STATE_COUNT);
    if ( set_thread_status != 0 )
    {
        rb_raise(rb_ePTraceError, "thread_set_state failed with error code: %d",
                 set_thread_status);
    }
    return Qnil;
#undef SET
}

#define REG_STRUCT_DEFINE()                                             \
    rb_struct_define("RegStruct",                                       \
                     "rax", "rbx", "rcx", "rdi", "rsi", "rbp", "rsp", "r8", \
                     "r9", "r10", "r11", "r12", "r13", "r14", "r15",    \
                     /*"rip", "rflags", "cs", "fs", "gs",*/             \
                     0)



static VALUE
ptrace_syscall(int argc, VALUE *argv, VALUE self)
{
    VALUE data = INT2FIX(0);
    if (argc == 1) {
	data = argv[0];
    }
    VALUE taskv = rb_ivar_get(self, id_ptrace_task);
    mach_port_t task = (mach_port_t)NUM2LONG(taskv);
    fprintf(stderr, "task_resuming\n");
    task_resume(task);
    fprintf(stderr, "task_resumed\n");
    return Qnil;
}

static VALUE
ptrace_alloc(VALUE mod, pid_t pid)
{
    /* setup PID */
    VALUE v = rb_obj_alloc(mod);
    rb_ivar_set(v, id_ptrace_pid, LONG2NUM(pid));
    /* setup task */
    mach_port_t task, myport, exception_port;
    myport = mach_task_self();
    task_for_pid(myport, pid, &task);
    rb_ivar_set(v, id_ptrace_task, LONG2NUM(task));
    /* setup exception port */
    mach_port_allocate(myport, MACH_PORT_RIGHT_RECEIVE, &exception_port);
    mach_port_insert_right(myport, exception_port, exception_port,
                           MACH_MSG_TYPE_MAKE_SEND);
    rb_ivar_set(v, id_ptrace_exception_port, LONG2NUM(exception_port));
    return v;
}

static VALUE
ptrace_wait(VALUE self)
{
    pid_t pid = get_pid(self);
    int st;
    VALUE taskv = rb_ivar_get(self, id_ptrace_task);
    mach_port_t task = (mach_port_t)NUM2LONG(taskv);
    fprintf(stderr, "task_suspending\n");
    task_suspend(task);
    fprintf(stderr, "task_suspended\n");
    fprintf(stderr, "waitpiding\n");
    
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

