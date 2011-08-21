require 'test/unit'
require 'ptrace'

class PTraceTest < Test::Unit::TestCase
  def test_ls
    pt = PTrace.exec('ls')
    e = pt.wait
    p e
    pt.cont

    while e = pt.wait
      p e
      case e
      when :SIGTRAP
        pt.cont :SIGUSR1
      when :SIGSEGV
        pt.syscall :SIGSEGV
      when :SIGUSR1
        pt.singlestep
      else
        pt.syscall e
      end
    end
  end
end

