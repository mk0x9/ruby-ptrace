#ifdef PT_GETREGS
static VALUE
ptrace_getregs(VALUE self)
{
    struct user_regs_struct urs;
    void *data_ptr = (void *)&urs;
    pid_t pid = get_pid(self);
    long ret;
    VALUE v = Qnil;

    CALL_PTRACE(ret, PT_GETREGS, pid, 0, data_ptr);
    
    v = rb_struct_new(rb_sPTraceRegStruct,
                      ULONG2NUM(urs.rax), ULONG2NUM(urs.rbx),
                      ULONG2NUM(urs.rcx), ULONG2NUM(urs.rdi),
                      ULONG2NUM(urs.rsi), ULONG2NUM(urs.rbp),
                      ULONG2NUM(urs.rsp), ULONG2NUM(urs.r8),
                      ULONG2NUM(urs.r9), ULONG2NUM(urs.r10),
                      ULONG2NUM(urs.r11), ULONG2NUM(urs.r12),
                      ULONG2NUM(urs.r13), ULONG2NUM(urs.r14),
                      ULONG2NUM(urs.r15), ULONG2NUM(urs.rip),
                      ULONG2NUM(urs.cs),
                      ULONG2NUM(urs.fs), ULONG2NUM(urs.gs));

    return v;
}
#else
UNSUPPORTED_API(ptrace_getregs, VALUE self)
#endif

#ifdef PT_SETREGS
static VALUE
ptrace_setregs(VALUE self, VALUE data)
{
    struct user_regs_struct urs;
    void *data_ptr = (void *)&urs;
    pid_t pid = get_pid(self);
    long ret;

#define SET(reg)                                                \
    {                                                           \
    VALUE v = rb_struct_getmember(data, rb_intern(#reg));       \
    urs.reg = NUM2ULONG(v);                                     \
    }
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
    SET(cs);
    SET(fs);
    SET(gs)
#undef SET

    CALL_PTRACE(ret, PT_SETREGS, pid, 0, data_ptr);
    return Qnil;
}
#else
UNSUPPORTED_API(ptrace_syscall, int argc, VALUE *argv, VALUE self)
#endif

#define REG_STRUCT_DEFINE()                                             \
    rb_struct_define("RegStruct",                                       \
                     "rax", "rbx", "rcx", "rdi", "rsi", "rbp",          \
                     "rsp", "r8", "r9", "r10", "r11", "r12",            \
                     "r13",                                             \
                     NULL)
