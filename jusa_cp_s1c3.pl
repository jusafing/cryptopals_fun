#!/usr/bin/perl -w
##############################################################################
# Description: Cryptopals Set 1 Challengue 3
# Syntax     : ./jusa_cp_s1c3.pl
# Author     : Morris [jusafing@jusanet.org]
##############################################################################

use strict;
my $SKIP_NON_ASCII = 1; # Cleaner output. Skip messages with non-ascii chars
my $MIN_C = 32;
my $MAX_C = 126;
my $TOP   = 3;          # TOP of candidates keys 
my $c = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

##############################################################################
sub xor_char {
    my ($a, $key, $msg, $freq, $freq_az, $ign) = @_;
    my $res   = $a ^ $key;
    my $a_i   = ord($a);
    my $key_i = ord($key);
    my $res_i = ord($res);
#    print "\tRES: $a XOR $key | $a_i XOR $key_i | RAW:($res) ORD:($res_i)\n";
    $msg->{$key_i} .= $res;
    $freq->{$key_i}{$res_i}++;
    if ( ($res_i > 64 && $res_i < 91) || ($res_i > 96 && $res_i < 123) ) {
        $freq_az->{$key_i}{$res_i}++;
    }
    else {
        $ign->{$key_i}++;
    }
}
##############################################################################
sub decrypt {
    my $c = shift;
    my (%msg, %freq, %freq_az, %chi, %ign);

    # http://en.algoritmy.net/article/40379/Letter-frequency-English
    my @eng = (
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074                   
    );

    for (my $key = $MIN_C; $key <= $MAX_C; $key++ ) {
        my $key_c = chr($key);
        $msg{$key} = "";
        foreach my $hex ($c =~ m/../g) {
            my $char = pack "H*", $hex;
            xor_char($char, $key_c, \%msg, \%freq, \%freq_az, \%ign);
        }
    }
    foreach my $key (sort{$a<=>$b} keys%{msg}) {
        my $flag = 0;

        ## OPTIONAL: 1st filter. discard non printable chars
        if ($SKIP_NON_ASCII == 1) {
            for (my $i = 1 ; $i < $MIN_C; $i++) { 
                if (exists  $freq{$key}{$i}){
                    #print "\tFound non printable value $i with key $key \n";
                    $flag = 1;
                }
            }
        }
        next if $flag == 1;

        # 2nd filter Chi2 http://bit.ly/2w3oSL7
        my $len_t  = length($msg{$key});
        my $len_w  = $len_t - $ign{$key};
        print "KEY: $key | TL: $len_t | LW: $len_w | IG: $ign{$key} | M: [ $msg{$key} ]\n";
        foreach my $i (keys%{$freq_az{$key}}) {
            my $eng_i = 0;
            if ($i > 96) { $eng_i = $i-97;}
            else {$eng_i = $i-65;} 
            my $diff = $freq_az{$key}{$i} - $len_w * $eng[$eng_i]; 
#            print "\tC: $i | FC:$freq_az{$key}{$i} | ENG: $eng[$eng_i]\n";
            $chi{$key} += ($diff * $diff) / ($len_w * $eng[$eng_i]);
        }
    }

    print "\n####################################################\n";
    print "The TOP $TOP of possible KEYS and DEC(m) (based on CHI2) are:\n\n";
    my $cnt = 1;
    foreach my $key (sort{$chi{$a}<=>$chi{$b}} keys%{chi}) {
        print "  > $cnt) KEY [$key] | M: $msg{$key}\n";
        $cnt++;
        last if ($cnt > $TOP);
    }
    print "\n####################################################\n";
    print "Morris [jusafing\@jusanet.org]\n";
}

decrypt($c);

