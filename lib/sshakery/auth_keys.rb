module Sshakery

    class AuthKeys
        # atomic writes
        require 'tempfile'
        require 'fileutils'

    # instance attributes
        # Instance state attributed
        INSTANCE_ATTRIBUTES = [ :errors,
            :raw_line,
            :path,
            :saved
        ]

        # attr used for auth key line (listed in order of appearance) 
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

        ATTRIBUTES = INSTANCE_ATTRIBUTES+KEY_ATTRIBUTES
        
        ATTRIBUTES.each do |attr|
            attr_accessor attr
        end

        DEFAULTS={
            :errors => []
        }.freeze
        
        # equal their name if true
        BOOL_ATTRIBUTES = [
            :no_agent_forwarding,
            :no_port_forwarding,
            :no_pty,
            :no_user_rc,
            :no_X11_forwarding
        ]
        
        # equal their value if set
        STR_ATTRIBUTES = [
            :key_type,
            :key_data,
            :note
        ]
        
        # each is equal to a joined string of their values
        ARR_STR_ATTRIBUTES = [
            :environment
        ]
        
        # add string and substitute attr value
        SUB_STR_ATTRIBUTES = {
            :command=>'command="%sub%"',
            :permitopen=>'permitopen="%sub%"',
            :tunnel=>'tunnel="%sub%"',
            :from=>'from="%sub%"'
        }

        # regex for matching ssh keys imported from a pub key file
        TYPE_REGEX = /ssh-dss|ssh-rsa/  
        B64_REGEX = /[A-Za-z0-9\/\+]+={0,3}/
        
        # additional regex for loading from auth keys file
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
        }
        
        ERRORS = {
            :data_modulus=> {:key_data=>'public key length is not a modulus of 4'}, 
            :data_short  => {:key_data=>'public key is too short'},
            :data_long   => {:key_data=>'public key is too long'},
            :data_char   => {:key_data=>'public key contains invalid base64 characters'},
            :data_nil    => {:key_data=>'public key is missing'},
            :type_nil    => {:key_type=>'missing key type'}
        }
    # class instance  attributes
        class << self; attr_accessor :path, :temp_path  end
        
    # class methods

        #return array of keys matching field
        def self.find_all_by(field,value, with_regex=false)
            result = []
            self.all.each do |auth_key|
                if with_regex
                    result.push auth_key if auth_key.send(field).match(value)
                else
                    result.push auth_key if auth_key.send(field) == value
                end
            end
            return result
        end
        
        def self.destroy(auth_key)
            self.write auth_key, destroy=true
        end

        def self.write(auth_key, destroy=false)
            lines = []
            FsUtils.lock_file(self.path) do |f|
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
        
        # return array of all keys in this file
        def self.all
           result = []
           File.readlines(self.path).each do |line|
                result.push( self.new(:raw_line => line ))
           end
           return result
        end

        
    # method attributes
        def initialize(args={}) 
            ATTRIBUTES.each do |attr|
                instance_variable_set("@#{attr}", args.has_key?( attr ) ? args[attr] : nil )
            end

            unless self.raw_line.nil? 
                self.load_raw_line
                self.saved = true
            end
        end
        
        # instantiate object based on contents of raw_line
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
        
        def all_no=(val)
            BOOL_ATTRIBUTES.each do |attr|
                self.instance_variable_set("@#{attr}",val)
            end
        end


        # return string representation of what attr will look like in auth file
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

        # validate and add a key to authorized keys file
        def save
            return false if not self.valid?
            return self.class.write(self)
        end

        # Raise an error if save doest pass validations
        def save!
            unless self.save 
                raise Sshakery::Errors::RecordInvalid.new 'Errors preventing save' 
            end
        end

        def destroy
            return false if not self.saved?
            return self.class.destroy self
        end
        
        # construct line for file
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

        def valid?
            self.errors = []

            if self.key_data.nil?:
                self.errors.push ERRORS[:data_nil] 
                return false
            end

            if self.key_type.nil?:
                self.errors.push ERRORS[:type_nil] 
                return false
            end
 
            if not self.key_data.match "^#{B64_REGEX}$":
                self.errors.push ERRORS[:data_char] 
            end

            if self.key_data.size < 30:
                self.errors.push ERRORS[:data_short] 
            end

            if self.key_data.size > 1000:
                self.errors.push ERRORS[:data_long] 
            end
            
            if self.key_data.size % 4 != 0:
                self.errors.push ERRORS[:data_modulus] 
            end

            return self.errors.empty?
        end

        def saved?
            return false if not self.valid?
            return self.saved           
        end

    end 



end
