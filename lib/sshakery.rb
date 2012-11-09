require "sshakery/version"
require "sshakery/fs_utils"
require "sshakery/auth_keys"
require "sshakery/errors"

# ===About
# Sshakery is a module for manipulating OpenSSH authorized_keys files
#
# * Some of its features include:
#
#   atomic writes
#
#   thread and process safe file locking (through flock)
#
#   method naming conventions similar to Rails
#
#   unit tests
#
# ===Usage
#
#    require 'sshakery'
#    
#    # instantiate key file object
#    keys = Sshakery.load '/path/to/.ssh/authorized_keys'
#
#    # return array of all keys
#    all_keys = keys.all
#    
#    # grab a single key
#    key = all_keys[0]
#
#    # return only keys where the note == 'foo'
#    somekeys = keys.find_all_by :note=>'foo'
#
#    # add forced command to key
#    key.command = 'ls'
#    key.save
module Sshakery
    
    ##
    # Load an authorized_keys file into an Authkeys class for manipulation
    # ===Args::
    # +path+  -> Path to authorized_keys file
    #
    # ===Returns::
    # +AuthKeys+ -> A new AuthKeys class configured to edit the path
    def self.load path
        new = Class.new(AuthKeys)
        new.path = path
        new.temp_path = 'sshakery.temp'
        return new
    end
end
