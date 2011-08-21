
require 'mkmf'

have_headers = true

%w{
  unistd.h errno.h
  sys/ptrace.h sys/types.h sys/user.h sys/wait.h
}.each{|h|
  have_headers = have_header(h)
  break unless have_headers
}
$objs = ["ptrace.o"]

if have_headers
  create_makefile('ptrace')
else
  raise("cannot create Makefile")
end
