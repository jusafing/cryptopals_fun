#!/usr/bin/perl -w
##############################################################################
# Description: Cryptopals Set 1 Challengue 4
# Syntax     : ./jusa_cp_s1c4.pl FILE
# Author     : Morris [jusafing@jusanet.org] September 2017
##############################################################################

use strict;
my $SKIP_NON_ASCII = 1; # Cleaner output. Skip messages with non-ascii chars
my $MIN_C  = 48;        # MIN value to consider non-ascii values
my $MAX_C  = 127;       # MAX value to consider non-ascii values
my $MAX_CL = 255;       # MAX Limit value to consider non-ascii values
my $MIN_CD = 32;        # MIN value for character used to try decrypt
my $MAX_CD = 126;       # MAX value for character used to try decrypt
my $TOP_I  = 2;         # TOP of candidates keys per iteration
my $TOP_A  = 5;        # TOP of candidates keys overall
my $MODE   = "hex";     # Decoding mode. input is string or encoded hex

##############################################################################
sub xor_char {
    my ($a, $key, $msg, $freq, $freq_az, $ign) = @_;
    my $res   = $a ^ $key;
    my $a_i   = ord($a);
    my $key_i = ord($key);
    my $res_i = ord($res);
    $freq->{$key_i}{$res_i}++;
    $msg->{$key_i} .= $res;
    if ( ($res_i > 64 && $res_i < 91) || ($res_i > 96 && $res_i < 123) ) {
        $freq_az->{$key_i}{$res_i}++;
    }
    else {
        $ign->{$key_i}++;
    }
}

##############################################################################
sub decrypt {
    my ($c, $dec) = @_;
    my (%msg, %freq, %freq_az, %chi, %ign, $candidate);

    # http://en.algoritmy.net/article/40379/Letter-frequency-English
    my @eng = (
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074                   
    );

    for (my $key = $MIN_CD; $key <= $MAX_CD; $key++ ) {
        my $key_c = chr($key);
        $msg{$key} = "";
        if ($MODE eq "hex") {
            foreach my $hex ($c =~ m/../g) {
                my $char = pack "H*", $hex;
                xor_char($char, $key_c, \%msg, \%freq, \%freq_az, \%ign);
            }
        }
        elsif ( $MODE eq "str") {
            foreach my $char (split //, $c) {
                xor_char($char, $key_c, \%msg, \%freq, \%freq_az, \%ign);
            }
        }
    }
    foreach my $key (sort{$a<=>$b} keys%{msg}) {

        ####  OPTIONAL: 1st filter. discard non printable chars
        my $flag = 0;
        if ($SKIP_NON_ASCII == 1) {
            for (my $i = 0 ; $i < $MIN_C; $i++) { 
                next if ($i == 10 || $i == 32 || $i ==39);
                $flag = 1 if (exists  $freq{$key}{$i});
            }
            for (my $i = $MAX_C ; $i < $MAX_CL; $i++) { 
                $flag = 1 if (exists  $freq{$key}{$i});
            }
            next if ($flag == 1);
            chomp $msg{$key};
        }

        ####  Analysis with Chi2 http://bit.ly/2w3oSL7
        my $len_t  = length($msg{$key});
        my $len_w  = $len_t - $ign{$key};
        foreach my $i (keys%{$freq_az{$key}}) {
            my $eng_i = 0;
            if ($i > 96) { $eng_i = $i-97;}
            else {$eng_i = $i-65;} 
            my $diff = $freq_az{$key}{$i} - $len_w * $eng[$eng_i]; 
#            print "\tC: $i | FC:$freq_az{$key}{$i} | ENG: $eng[$eng_i]\n";
            $chi{$key} += ($diff * $diff) / ($len_w * $eng[$eng_i]);
        }
#        print "C: $c | KEY: $key | CH: $chi{$key} | TL: $len_t | LW: $len_w | IG: $ign{$key} | M: [ $msg{$key} ]\n";
    }
    my $cnt = 1;
    foreach my $key (sort{$chi{$a}<=>$chi{$b}} keys%{chi}) {
        print "[$c] $cnt) KEY [$key] | CH: $chi{$key} | M: $msg{$key}\n";
        $cnt++;
        $dec->{"$c|--|$key|--|$msg{$key}"} = $chi{$key};
        last if ($cnt > $TOP_I);
    }
}

##############################################################################
sub search_msg {
    my $file = shift;
    my %dec ;
    open(FILE, "$file") || die "ERROR, unable to open file $file\n\n";
    while(<FILE>) {
        chomp($_);
        decrypt($_, \%dec);
    }
    close(FILE);
    print "\n####################################################\n";
    print "The TOP $TOP_A of possible KEYS and DEC(m) (based on CHI2) are:\n\n";
    my $cnt = 1;
    foreach my $id (sort{$dec{$a}<=>$dec{$b}} keys%{dec}) {
        print "$cnt) C-K-M: $id | CH: $dec{$id}\n";
        $cnt++;
        last if ($cnt > $TOP_A);
    }
    print "\n####################################################\n";
}

search_msg($ARGV[0]);

