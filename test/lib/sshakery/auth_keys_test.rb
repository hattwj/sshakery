require 'test/test_helper'

describe Sshakery::AuthKeys do
    # create a copy of test data to manipulate
    before do
        @errors = Sshakery::AuthKeys::ERRORS
        @temp = Tempfile.new('nofail')
        src = "#{$dir}/fixtures/sshakery_nofail_fixture.txt" 
        FileUtils.cp src, @temp.path
        @keys = Sshakery.new(@temp.path)
        @key = @keys.new
    end

    # close temp file (should autoremove)
    after do
        @temp.close
        @temp.unlink
    end
    
    describe "class behavior" do
        it "must be defined" do
            Sshakery::AuthKeys.wont_be_nil
        end

        it "must perform atomic writes" do
        end
        # mutex writes
        ## lock and overwrite
        # safe reads when unlocked only
        # 


        #it "must lock the file while writing" do
        #    keys1 = Sshakery.new(@temp.path)
        #    keys1.temp_path='more'
        #    ts=[]
        #    puts @temp.readlines
    
        #    File.open(@temp.path) do |f|
        #        keys1.all.each do |key|
        #            
        #            t =Thread.new{
        #                (1..50).each do |i|
        #                    puts i
        #                    key.all_no =true
        #                    key.save
        #                    puts "#{i.to_s} done"
        #                end
        #            }
        #            ts.push t
        #        end
        #        ts.each{|t|t.join}
        #        #failed_val = lambda { keys[0].save }
        #        #failed_val.must_raise RuntimeError
        #        #error = failed_val.call rescue $!
        #        #error.message.must_include "cannot generate tempfile '#{@temp.path}'"
        #    end

        #end

        it "must be able to perform backup rotation" do

        end

    end

    # instance behavior
    it "must not validate when empty" do
        key=@keys.new
        key.valid?.must_equal false
        key.errors.wont_be_empty
    end

    it "must not save when empty" do
        key=@keys.new
        key.save.must_equal false
    end

    it "must raise error on save! with invalid data" do
        key = @keys.new
        failed_val = lambda { key.save! }
        failed_val.must_raise Sshakery::Errors::RecordInvalid
        error = failed_val.call rescue $!
        error.message.must_include "Errors preventing save"
    end

    it "must have errors when generated line is incomplete" do
        key = @keys.new
        key.all_no = true
        key.gen_raw_line.must_be_nil
        key.errors.wont_be_empty
    end
        
    it "must accept valid b64 key_data" do
        key = @keys.new
        key.key_type = 'ssh-rsa'
        key.key_data = 'badfhk55'*20
        key.valid?.must_equal true
    end
    
    it "must reject invalid b64 characters" do
        key = @keys.new
        key.key_type = 'ssh-rsa'
        key.key_data = 'baaAa$@'*40
        key.valid?.must_equal false
        key.errors.include?(@errors[:data_char]).must_equal true
        key.key_data = 'ba ,a$@'*40
        key.valid?.must_equal false
        key.errors.include?(@errors[:data_char]).must_equal true
    end
    
    it "must only accept b64 modulus 4 data" do
        key = @keys.new
        key.key_type = 'ssh-rsa'
        key.key_data = 'baa'*40
        key.valid?.must_equal true
        key.key_data = 'baa'*41
        key.valid?.must_equal false
        key.errors.include?(@errors[:data_modulus]).must_equal true
    end

    it "must reject short key_data" do
        key = @keys.all[0]
        key.key_data = 'baaAa12'*4
        key.valid?.must_equal false
        key.errors.include?(@errors[:data_short]).must_equal true
    end

    it "must reject long key_data" do
        key = @keys.all[0]
        key.key_data = 'baaAa123'*400
        key.valid?.must_equal false
        key.errors.include?(@errors[:data_long]).must_equal true
    end

end

