typedef enum __ptrace_request ptrace_request;

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
		      ULONG2NUM(urs.ebx), ULONG2NUM(urs.ecx),
                      ULONG2NUM(urs.edx),
		      ULONG2NUM(urs.esi), ULONG2NUM(urs.edi),
                      ULONG2NUM(urs.ebp),
		      ULONG2NUM(urs.eax), ULONG2NUM(urs.xds),
                      ULONG2NUM(urs.xes),
		      ULONG2NUM(urs.xfs), ULONG2NUM(urs.xgs),
                      ULONG2NUM(urs.orig_eax),
		      ULONG2NUM(urs.eip), ULONG2NUM(urs.xcs),
                      ULONG2NUM(urs.eflags),
		      ULONG2NUM(urs.esp), ULONG2NUM(urs.xss));
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
    
    SET(ebx);
    SET(ecx);
    SET(edx);
    SET(esi);
    SET(edi);
    SET(ebp);
    SET(eax);
    SET(xds);
    SET(xes);
    SET(xfs);
    SET(xgs);
    SET(orig_eax);
    SET(eip);
    SET(xcs);
    SET(eflags);
    SET(esp);
    SET(xss);
#undef SET

    CALL_PTRACE(ret, PT_SETREGS, pid, 0, data_ptr);
    return Qnil;
}
#else  /* PT_SETREGS */
UNSUPPORTED_API(ptrace_setregs, VALUE self, VALUE data)
#endif

#define REG_STRUCT_DEFINE()                                             \
    rb_struct_define("RegStruct",                                       \
                     "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "xds", \
                     "xes", "xfs", "xgs", "orig_eax", "eip", "xcs",     \
                     "eflags", "esp", "xss", 0)
