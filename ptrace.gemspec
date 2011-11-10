# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)
 
require 'ptrace/version'
 
Gem::Specification.new do |s|
  s.name              = 'ptrace'
  s.version           = PTrace::VERSION
  s.platform          = Gem::Platform::RUBY
  s.authors           = ['Koichi Sasada', 'garaemon']
  s.email             = ['jdleesmiller@gmail.com']
  s.homepage          = 'https://github.com/jdleesmiller/ruby-ptrace'
  s.summary           = %q{Wrapper for ptrace.}
  s.description       = %q{Wrapper for ptrace.}

  s.rubyforge_project = ''

  s.files       = Dir.glob('{lib}/**/*.rb').concat Dir.glob('ext/{*.rb,*.c}')
  s.test_files  = Dir.glob('test/*_test.rb')

  s.extensions = "ext/extconf.rb"
  s.require_paths << 'ext'
end

