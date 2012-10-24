require "sshakery/version"
require "sshakery/auth_keys"
module Sshakery
    # instantiate a new Authkey class
    def self.new path
        new = Class.new(AuthKeys)
        new.path = path
        new.temp_path = new.path + '.tmp'
        return new
    end
end
