require 'test/test_helper'

describe Sshakery::FsUtils do
    it "must lock for writes" do
        # a large offset to create large writes
        offset = 10**600

        #test file for testing atomic writes and locking
        temp = Tempfile.new 'flock'
        ts=[]
        (1..50).each do |i|
            t =Thread.new{
                sleep rand/3
                # update a counter using atomic writes and a file lock
                Sshakery::FsUtils.atomic_lock( :path=>temp.path, :lock_path=>'./hhh' ) do |f|
                    (1..50).each do |j|
                        f.rewind
                        val = f.read.to_i
                        #write number to file
                        val = val>0 ? val+1 : offset+1
                        f.rewind
                        f.truncate f.pos
                        f.write "#{val}\n"
                        f.flush
                        f.rewind
                    end
                end
            }
            ts.push t
        end
        ts.each{|t| t.join}
        File.open(temp.path).read.to_i.must_equal offset+2500
        temp.close
        temp.unlink
    end
end
