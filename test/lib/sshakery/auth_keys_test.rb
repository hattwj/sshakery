require 'test/test_helper'

describe Sshakery::AuthKeys do
    # create a copy of test data to manipulate
    before do
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

    it "must be defined" do
        Sshakery::AuthKeys.wont_be_nil
    end

    it "must not validate when empty" do
        @key.valid?.must_equal false
        @key.errors.wont_be_empty
    end

    it "must not save when empty" do
        @key.save.must_equal false
    end

    it "must raise error on save! with invalid data" do
        failed_val = lambda { @key.save! }
        failed_val.must_raise Sshakery::Errors::RecordInvalid
        error = failed_val.call rescue $!
        error.message.must_include "Errors preventing save"
    end

    it "must have errors when generated line is incomplete" do
        @key.all_no = true
        @key.gen_raw_line.must_be_nil
        @key.errors.wont_be_empty
    end
end

