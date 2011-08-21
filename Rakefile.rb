require 'rake/testtask'
require 'rake/clean'

desc 'build extension'
task :ext do
  Dir.chdir('ext') do
    ruby "extconf.rb"
    sh "make"
  end
end

Rake::TestTask.new(:test) do |t|
  t.libs << %w(lib ext)
  t.pattern = 'test/**/*_test.rb'
end

CLEAN.include('ext/*{.o,.log}')
CLEAN.include('ext/Makefile')
CLOBBER.include('ext/*.so')

task :default => :test

