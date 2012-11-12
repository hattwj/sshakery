module Sshakery
##
# == AuthKeys
# The AuthKeys class is the main part of this gem and is responsible
# for reading from and writing to an authorized_keys file.

class AuthKeys
    # atomic writes
    require 'tempfile'
    require 'fileutils'

# instance attributes

    ##
    # Attributes that help define the current state of the key
    STATE_ATTRIBUTES = [ 
        :errors,
        :raw_line,
        :saved
    ]

    ##
    # :category: Instance Attributes
    # Attributes that are read from / written to authorized_keys files. 
    # They are listed in the order that they should appear in the authorized_keys file 
    # 
    # 
    # [command]                 (string) -> A forced shell command to run
    #                               key.command = 'ls'
    #
    # [permitopen]              (string) -> TODO: document
    # 
    # [tunnel]                  (integer) -> Port forwarding
    #                               key.tunnel = 5950
    #
    # [from]                    (string) -> IP/host address required for client
    #
    # [environment]             (array) -> Array of strings to set shell environment variables
    #                           Not tested
    #                              key.environment.push 'RAILS_ENV=production'
    #
    # [no_agent_forwarding]     (boolean) -> Don't allow ssh agent authentication forwarding::
    #                           
    #
    # [no_port_forwarding]      (boolean) -> Don't allow port forwarding
    #
    # [no_pty]                  (boolean) -> Don't create terminal for client
    #
    # [no_user_rc]              (boolean) -> Don't process user rc files
    #
    # [no_X11_forwarding]       (boolean) -> Don't allow X11 forwarding.
    #                           Please note the uppercase 'X' in X11
    #
    # [key_type]                (string) -> Type of key. 'ssh-dsa' or 'ssh-rsa'
    #
    # [key_data]                (string) -> A Base64 string of public key data
    #
    # [note]                    (string) -> A note about a key. No spaces allowed
    #
    KEY_ATTRIBUTES =[
        :command,
        :permitopen,
        :tunnel,
        :from,
        :environment,
        :no_agent_forwarding,
        :no_port_forwarding,
        :no_pty,
        :no_user_rc,
        :no_X11_forwarding,
        :key_type,
        :key_data,
        :note
    ]

    ##
    # A list of all attributes a key has
    ATTRIBUTES = STATE_ATTRIBUTES+KEY_ATTRIBUTES #:nodoc:
    
    ##
    # set attributes
    ATTRIBUTES.each do |attr| #:nodoc:
        attr_accessor attr
    end

    ##
    # Attribute default values
    DEFAULTS={
        :errors => []
    }.freeze 
    
    ##
    # Boolean attributes 
    BOOL_ATTRIBUTES = [
        :no_agent_forwarding,
        :no_port_forwarding,
        :no_pty,
        :no_user_rc,
        :no_X11_forwarding
    ] #:nodoc:
    
    ##
    # STR_ATTRIBUTES is a list of attributes that are strings
    # - +gen_raw_line+ will return a line containing the contents of these variables (if any)
    STR_ATTRIBUTES = [
        :key_type,
        :key_data,
        :note
    ] #:nodoc:
    

    # each is equal to a joined string of their values
    # - +gen_raw_line+ will return a line containing the contents 
    # of these variables (if any)
    ARR_STR_ATTRIBUTES = [
        :environment
    ] #:nodoc:
    
    # add string and substitute attr value
    # - +gen_raw_line+ will return a line containing the contents of these variables (if any)
    SUB_STR_ATTRIBUTES = {
        :command=>'command="%sub%"',
        :permitopen=>'permitopen="%sub%"',
        :tunnel=>'tunnel="%sub%"',
        :from=>'from="%sub%"'
    } #:nodoc:

    ##
    # A regex for matching ssh key types imported from a pub key file
    TYPE_REGEX = /ssh-dss|ssh-rsa/

    ##
    # A regex for matching base 64 strings
    B64_REGEX = /[A-Za-z0-9\/\+]+={0,3}/
    
    ##
    # The regex used for reading individual lines/records in an authorized_keys file
    OPTS_REGEX = {
        :key_type=> /(#{TYPE_REGEX}) (?:#{B64_REGEX})/,
        :key_data=> /(?:#{TYPE_REGEX}) (#{B64_REGEX})/,
        :note=>/([A-Za-z0-9_\/\+@]+)\s*$/,
        :command=>/command="([^"]+)"(?: |,)/,
        :environment=>/([A-Z0-9]+=[^\s]+)(?: |,)/,
        :from=>/from="([^"])"(?: |,)/,
        :no_agent_forwarding=>/(no-agent-forwarding)(?: |,)/,
        :no_port_forwarding=>/(no-port-forwarding)(?: |,)/,
        :no_pty=>/(no-pty)(?: |,)/,
        :no_user_rc=>/(no-user-rc)(?: |,)/,
        :no_X11_forwarding=>/(no-X11-forwarding)(?: |,)/,
        :permitopen=>/permitopen="([a-z0-9.]+:[\d]+)"(?: |,)/,
        :tunnel=>/tunnel="(\d+)"(?: |,)/
    } #:nodoc:
    
    ##
    # This is a list of attribute errors
    ERRORS = {
        :data_modulus=> {:key_data=>'public key length is not a modulus of 4'}, 
        :data_short  => {:key_data=>'public key is too short'},
        :data_long   => {:key_data=>'public key is too long'},
        :data_char   => {:key_data=>'public key contains invalid base64 characters'},
        :data_nil    => {:key_data=>'public key is missing'},
        :type_nil    => {:key_type=>'missing key type'},
        :bool        => 'bad value for boolean field'
    }

    # class instance attributes
    class << self; 
        # Path to authorized_keys file
        attr_accessor :path

        # Path to lock file (cannot be the same as key file)
        attr_accessor :temp_path  
    end 

    ##
    # Search the authorized_keys file for keys containing a field with a specific value 
    #
    # *Args*    :
    # - +fields+ -> A hash of key value pairs to match against
    # - +with_regex+ -> Use regex matching (default=false)
    #
    # *Returns* :
    # - +Array+ -> An array of keys that matched
    #
    # *Usage*   :
    #      keys = Sshakery.load '/home/someuser/.ssh/authorized_keys'
    #      foo_keys = keys.find_all_by :note=>'foo'
    #      fc_keys = keys.find_all_by :command=>'ls', :no_X11_forwarding=>true
    #      rsa_keys = keys.find_all_by :key_data=>'ssh-rsa'
    # 
    def self.find_all_by(fields ={}, with_regex=false)
        result = []
        
        self.all.each do |auth_key|
            
            all_matched = true

            fields.each do |field,value|
                if with_regex &&  auth_key.send(field).to_s.match(value.to_s)
                    next
                elsif auth_key.send(field) == value
                    next
                end
                all_matched = false
            end
            
            result.push auth_key if all_matched

        end
        return result
    end
    
    ##
    # Delete a key
    def self.destroy(auth_key)
        self.write auth_key, destroy=true
    end
    
    ##
    # Create, update or delete the contents of a key
    def self.write(auth_key, destroy=false)
        lines = []
        FsUtils.atomic_lock(:path=>self.path) do |f|
            f.each_line do |line|
                key=self.new(:raw_line => line )

                if key.key_data == auth_key.key_data 
                    lines.push auth_key.gen_raw_line if destroy==false
                else
                    lines.push line 
                end
            end
            f.rewind
            f.truncate(0)
            lines.each do |line|
                f.puts line
            end
        end
    end
    
    ##
    # Return array of all keys
    def self.all
       result = []
       File.readlines(self.path).each do |line|
            result.push( self.new(:raw_line => line ))
       end
       return result
    end
    
    ##
    # Create a new key object
    def initialize(args={}) 
        ATTRIBUTES.each do |attr|
            instance_variable_set("@#{attr}", args.has_key?( attr ) ? args[attr] : nil )
        end

        unless self.raw_line.nil? 
            self.load_raw_line
        end
    end
    
    ##
    # Instantiate key object based on contents of raw_line
    def load_raw_line
        self.raw_line.chomp!
        OPTS_REGEX.each do |xfield,pattern|
            field = "@#{xfield}"
            m= self.raw_line.match pattern
            next if m.nil?
            #p "#{field} => #{m.inspect}" 
            if BOOL_ATTRIBUTES.include? xfield
                self.instance_variable_set(field, true)
                next  
            end

            if STR_ATTRIBUTES.include? xfield 
                self.instance_variable_set(field,  m[1])
                next
            end

            if ARR_STR_ATTRIBUTES.include? xfield 
                self.instance_variable_set(field, m.to_a)
                next
            end

            if SUB_STR_ATTRIBUTES.include? xfield 
                self.instance_variable_set(field, m[1])
                next
            end 

        end
    end

    ##
    # Set all boolean attributes at the same time
    # - +val+ -> (boolean)
    def all_no=(val)
        BOOL_ATTRIBUTES.each do |attr|
            self.instance_variable_set("@#{attr}",val)
        end
    end

    ## 
    # Return the string representation of what the attribute will look like in the authorized_keys file
    # 
    # *Args*  :
    # - +field+ -> Attribute name
    #
    # *Returns* :
    # - +string+ -> A string representation of the attribute
    def raw_getter field
        val = self.instance_variable_get("@#{field}")
        return nil if val.nil? == true ||  val == false

        if BOOL_ATTRIBUTES.include? field
            return field.to_s.gsub '_', '-'   
        end

        if STR_ATTRIBUTES.include? field 
            return val 
        end

        if ARR_STR_ATTRIBUTES.include? field && val.empty? == false 
            return val.join ' '
        end

        if SUB_STR_ATTRIBUTES.include? field 
            return SUB_STR_ATTRIBUTES[field].sub '%sub%', val  
        end 
    end

    ##
    # Add a key to authorized keys file if it passes validation.
    # If the validations fail the reason for the failure will be
    # found in @errors.
    #
    # *Returns* :
    # - +boolean+   -> True if save was successful, otherwise returns false
    def save
        return false if not self.valid?
        return self.class.write(self)
    end

    ##
    # Add a key to authorized keys file if it passes validation, otherwise
    # raise an error if save doesn't pass validations
    #
    # *Returns* :
    # - +boolean+   -> True if save was successful, otherwise raises error
    #
    # *Raises* :
    # - +Error+ -> Sshakery::Errors::RecordInvalid ( Key did not pass validations )
    def save!
        unless self.save 
            raise Sshakery::Errors::RecordInvalid.new 'Errors preventing save' 
        end
    end
    
    ##
    # Remove a key from the file
    #
    # *Returns*    :
    # - +Boolean+   -> Destroy success status
    def destroy
        return false if not self.saved?
        return self.class.destroy self
    end
    
    ##
    # Construct the line that will be written to file
    #
    # *Returns* :
    # - +String+    -> Line that will be written to file
    def gen_raw_line
        return nil unless self.valid?
        line = ''
        data = []
        SUB_STR_ATTRIBUTES.each do |field,field_regex|
            val = self.raw_getter field
            data.push val if val.nil? == false
        end
        unless data.empty?
            line = "#{data.join ' ,'}"
        end

        data = []
        BOOL_ATTRIBUTES.each do |field|
            val = self.raw_getter field
            data.push val if val.nil? == false
        end
        unless data.empty?
            if line == ''
                line += "#{data.join ','} "
            else
                line += ",#{data.join ','} "
            end
        end

        data = []
        ARR_STR_ATTRIBUTES.each do |field|
            val = self.raw_getter field
            data.push val if val.nil? == false
        end
        unless data.empty?
            if line == ''
                line += "#{data.join ','} "
            else
                line += ", #{data.join ','} "
            end
        end

        data = []
        STR_ATTRIBUTES.each do |field|
            val = self.raw_getter field
            data.push val if val.nil? == false
        end
        line += data.join ' '
        return line
    end

    ##
    # Validate the key
    # If the validations fail the reason for the failure will be
    # found in @errors.
    #
    # *Returns* :
    # - +Boolean+   -> True if valid, otherwise false
    def valid?
        self.errors = []
        
        BOOL_ATTRIBUTES.each do |field|
            val = self.raw_getter field
            unless val.nil? == true || val == true || val == false
                self.errors.push field=>ERRORS[:bool]
            end
        end
        
        if self.key_data.nil?
            self.errors.push ERRORS[:data_nil] 
            return false
        end

        if self.key_type.nil?
            self.errors.push ERRORS[:type_nil] 
            return false
        end

        if not self.key_data.match "^#{B64_REGEX}$"
            self.errors.push ERRORS[:data_char] 
        end

        if self.key_data.size < 30
            self.errors.push ERRORS[:data_short] 
        end

        if self.key_data.size > 1000
            self.errors.push ERRORS[:data_long] 
        end
        
        if self.key_data.size % 4 != 0
            self.errors.push ERRORS[:data_modulus] 
        end

        return self.errors.empty?
    end

    ##
    # Has the key already been saved to file?
    #
    # *Returns*    :
    # - +Boolean+   -> True if has been saved before, otherwise false
    def saved?
        return false if not self.valid?
        return self.saved           
    end
end
end 
