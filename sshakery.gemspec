# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sshakery/version'

Gem::Specification.new do |gem|
  gem.name          = "sshakery"
  gem.version       = Sshakery::VERSION
  gem.authors       = ["hattb"]
  gem.email         = ["hattwj@yahoo.com"]
  gem.description   = %q{A ruby gem for manipulating OpenSSH authorized_keys files}
  gem.summary       = %q{TODO: Write a gem summary}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
end
