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
# ===Help
# For more information regarding wich options are supported please run:
#    man sshd
# Additionally here are some good articles:
#
# http://www.eng.cam.ac.uk/help/jpmg/ssh/authorized_keys_howto.html
#
# http://www.hackinglinuxexposed.com/articles/20030109.html 
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
#    # add forced command to key
#    key.command = 'ls'
#    key.save
#
#    # return only keys where the note == 'foo'
#    somekeys = keys.find_all_by :note=>'foo'
#
#    # return only keys where the note == 'foo' and the key_type == 'ssh-rsa'
#    somekeys = keys.find_all_by :note=>'foo', :key_type=>'ssh-rsa'
#
module Sshakery
    
    ##
    # Load an authorized_keys file and return an Authkeys class for manipulation
    # ===Args   :
    # +path+  -> Path to authorized_keys file
    #
    # +lock_path+  -> Path to shared lock file
    #
    # ===Returns    :
    # +AuthKeys+ -> A new AuthKeys class configured to edit the path
    def self.load path, lock_path=nil
        new = Class.new(AuthKeys)
        new.path = path
        new.temp_path = lock_path || 'sshakery.temp'
        return new
    end
end
