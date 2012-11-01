require "sshakery/version"
require "sshakery/fs_utils"
require "sshakery/auth_keys"
require "sshakery/errors"

module Sshakery
    # instantiate a new Authkey class
    def self.new path
        new = Class.new(AuthKeys)
        new.path = path
        new.temp_path = 'sshakery.temp'
        return new
    end
end
