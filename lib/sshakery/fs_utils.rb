# File system tools used by Sshakery
module Sshakery::FsUtils
    require 'tempfile' unless defined?(Tempfile)
    require 'fileutils' unless defined?(FileUtils)
    
    ##
    # Write to file atomically while maintaining an exclusive lock
    # - Cannot lock actual file, the atomic mv operation breaks the flock
    # - Exclusive flock only works if all processes use the same 
    # lock file (this will happen automatically by default)
    # - Atomic writes are achieved by fs move operation 
    #
    # ===Usage
    #    fpath = '/home/user/.ssh/authorized_keys'
    #    Sshakery::FsUtils.atomic_lock(:path=>fpath) do |f|
    #       f.write 'Awesome atomic writes, now with locks as well!'
    #    end
    #
    # ===Args
    # - +path+ -> (required) Path to auth_keys file
    # - +lock_name+ -> (optional) Path to lock file
    #
    # ===Yields
    # - +file_object+ -> File object used for atomic writes
    #
    def self.atomic_lock(opts={:path=>nil,:lock_name=>nil}, &block)
        file_name = opts[:path]
        opts[:lock_name] = file_name+'.lockfile' unless opts[:lock_name]
        lock_name = opts[:lock_name]

        # create lock_file if it doesnt exist
        FileUtils.touch(lock_name)
        self.lock_file(lock_name) do |f|
            # write details of lock
            f.truncate 0
            f.puts self.lock_info
            f.flush

            # yield for atomic writes
            self.atomic_write(file_name) do |temp_file|
                yield temp_file
            end
        end
    end

    # lock a file 
    #
    # ===Usage
    #    fpath = '/home/user/.ssh/authorized_keys'
    #    Sshakery::FsUtils.lock_file(:path=>fpath) do |f|
    #       f.write 'Awesome locking writes!'
    #    end
    #
    # ===Args
    # +path+ -> (required) Path to auth_keys file
    # +lock_name+ -> (optional) Path to lock file
    #
    # ===Yields
    # +file_object+ -> File object used for atomic writes
    #
    def self.lock_file(file_name, &block) #:nodoc:
        f = File.open(file_name, 'r+')
        begin
            f.flock File::LOCK_EX
            yield f
        ensure
            f.flock File::LOCK_UN unless f.nil?
        end
    end
    
    # aquire shared lock for reading a file
    def self.read(file_name, &block) #:nodoc:
        f = File.open(file_name, 'r')
        f.flock File::LOCK_SH
        puts "sh locked #{file_name}"
        yield f
    ensure
        puts "sh unlocked #{file_name}"
        f.flock File::LOCK_UN
    end

  ##
  # ===Source copied from:
  # * https://github.com/rails/rails/blob/master/activesupport/lib/active_support/core_ext/file/atomic.rb
  #
  # Write to a file atomically. Useful for situations where you don't
  # want other processes or threads to see half-written files.
  #
  #   File.atomic_write('important.file') do |file|
  #     file.write('hello')
  #   end
  #
  # If your temp directory is not on the same filesystem as the file you're
  # trying to write, you can provide a different temporary directory.
  #
  #   File.atomic_write('/data/something.important', '/data/tmp') do |file|
  #     file.write('hello')
  #   end
  def self.atomic_write(file_name, temp_dir = Dir.tmpdir)
    temp_file = Tempfile.new(File.basename(file_name), temp_dir)
    temp_file.binmode
    FileUtils.cp(file_name,temp_file.path)
    yield temp_file
    temp_file.close

    if File.exists?(file_name)
      # Get original file permissions
      old_stat = File.stat(file_name)
    else
      # If not possible, probe which are the default permissions in the
      # destination directory.
      old_stat = probe_stat_in(dirname(file_name))
    end
    
    # Overwrite original file with temp file
    FileUtils.mv(temp_file.path, file_name) 

    # Set correct permissions on new file
    begin
      File.chown(old_stat.uid, old_stat.gid, file_name)
      # This operation will affect filesystem ACL's
      File.chmod(old_stat.mode, file_name)
    rescue Errno::EPERM
      # Changing file ownership failed, moving on.
    end
  end

  # Private utility method.
  def self.probe_stat_in(dir) #:nodoc:
    basename = [
      '.permissions_check',
      Thread.current.object_id,
      Process.pid,
      rand(1000000)
    ].join('.')

    file_name = join(dir, basename)
    FileUtils.touch(file_name)
    File.stat(file_name)
  ensure
    FileUtils.rm_f(file_name) if file_name
  end
    
    ##
    # *Not used yet*::
    # lock file details to write to disk
    def self.lock_info #:nodoc:
        return [
          'Sshakery-lockfile',
          Thread.current.object_id,
          Process.pid,
          Time.now.to_i,
          rand(1000000)
        ].join(' ')
        
    end

end
