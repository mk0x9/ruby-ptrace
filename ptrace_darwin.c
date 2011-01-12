typedef int ptrace_request;

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

