package Crypt::ECDH;

use 5.008001;
use strict;
use warnings;
use Carp;
require Exporter;
use English;
use base qw( Exporter );

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::ECDH ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw( new_ec_keypair get_ec_pub_key get_ecdh_key

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(
	
);

our $VERSION = '0.10';

use Inline C => 'DATA',
   # VERSION => '0.10',
    NAME => 'Crypto::ECDH';

use Inline C => Config => (
    INC =>  '-I/opt/local/include -I/usr/local/include',
    LIBS => '-L/opt/local/lib -L/usr/local/lib -lcrypto',
    ENABLE => 'UNTAINT',
    DIRECTORY => '/usr/local/lib/perl_inline',
    #CLEAN_AFTER_BUILD => 0,
);
Inline->init;

sub new_ec_keypair{
  my $group_nid = shift;
  my $key;

  if( (!defined $group_nid) or ($group_nid eq "") ){
    croak("Missing parameter EC NID");
  }

  if( $group_nid !~ /[0-9]+/ ){
    croak("parameter EC NID is not numeric");
  }
	
  eval { $key = Crypt::ECDH::__new_ec_keypair($group_nid); };

  if ( $@ ne "" )
  {
     croak($@);
  }   

  return $key 

}

sub get_ec_pub_key {
 
 my $ECKey = shift;
 my $pubkey;

 if( (!defined $ECKey) or ($ECKey eq "") ){
    croak("Missing parameter ECKey");
 }
 
  $pubkey = Crypt::ECDH::__get_ec_pub_key($ECKey);

 return $pubkey;
}

sub get_ecdh_key {
  my $in_pub_ec_key = shift;
  my $ecdhkey;
  my $out_ec_key= shift;
  my $out_ec_pub_key= "";
  
  if( (!defined $in_pub_ec_key) or ($in_pub_ec_key eq "") ){
    croak("Missing parameter EC Peer PubKey");
  }

  if( (!defined $out_ec_key) ){
     $out_ec_key = "";
  }	
  

  eval { $ecdhkey = Crypt::ECDH::__get_ecdh_key($in_pub_ec_key,$out_ec_key,$out_ec_pub_key);};

  if ( $@ ne "" )
  {
     croak($@);
  }   

  return { 'ECDHKey' => $ecdhkey ,
           'PEMECKey' => $out_ec_key , 
           'PEMECPubKey' => $out_ec_pub_key };

}




1;

__DATA__

=pod

=cut

__C__

#include <openssl/opensslconf.h>	/* for OPENSSL_NO_ECDH */
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>


#ifdef OPENSSL_NO_ECDH
int main(int argc, char *argv[])
{
    croak("No ECDH support\n");
    return(0);
}
#else
#endif


/*Generate a new EC Keypair by openSSL nid
 *  
 *	
 *
 */
SV * __new_ec_keypair(SV* group_nid ){

    EC_KEY *ec_key;
    BIO 	*out = NULL;
    long r=0, len=0;
    unsigned char * outkey= NULL;
    SV *key = NULL;

    //get new EC curve by ID 
    ec_key = EC_KEY_new_by_curve_name(SvIV(group_nid));

    if(!EC_KEY_generate_key(ec_key))
    {
        //if there was an error generating the key free the key memory
        EC_KEY_free(ec_key);
	croak("EC key generation failed");
    }
	
    //Set flag to use Key encoding using NID instead of an explicit EC curve 
    EC_KEY_set_asn1_flag(ec_key,OPENSSL_EC_NAMED_CURVE);
	
    out = BIO_new(BIO_s_mem());
    r = PEM_write_bio_ECPrivateKey(out, ec_key, NULL, NULL, 0, NULL, NULL);
    BIO_flush(out);
    len = BIO_get_mem_data(out, NULL);

    outkey = (unsigned char * )malloc(len+1);
    len = BIO_read(out, outkey,len);
    outkey[len]='\0';

    key = newSVpvn(outkey ,len);

    /* Clean up allocated memory */
    BIO_free(out);
    EC_KEY_free(ec_key);
    //free(outkey);

    return key;
}


/*
 * extract the EC pub key from an ASN.1 encoded EC keypair
 * the key string needs to be terminated by a '\0'
 *
 */
SV * __get_ec_pub_key( SV *in ){

    EC_KEY *ec_key;
    BIO 	*in_eckey = NULL , *out_ec_pub_key;
    long r=0, len=0;
    char *outkey;
    SV *key = NULL;

    in_eckey = BIO_new(BIO_s_mem());
    len = BIO_puts(in_eckey, SvPV(in, PL_na) );
    //printf("\n BIP_puts written: %d ", len);
    
    ec_key = PEM_read_bio_ECPrivateKey(in_eckey, NULL,NULL,NULL);  
    
    out_ec_pub_key =BIO_new(BIO_s_mem());

    r = PEM_write_bio_EC_PUBKEY(out_ec_pub_key ,ec_key);
    len = BIO_get_mem_data(out_ec_pub_key,NULL);
    outkey = (unsigned char* ) malloc (len+1);
    r = BIO_read(out_ec_pub_key, outkey,len);
    outkey[len]= '\0';
    key = newSVpvn(outkey ,len);

    /* Clean up allocated memory */
    EC_KEY_free(ec_key);
    BIO_free(in_eckey);
    BIO_free(out_ec_pub_key);
    free(outkey);
 
    return key;

}

/*
 * generate Session key, based on a pub key already supplied
 * generate a new keypair and return a new private and public key 
 *
 */

SV * __get_ecdh_key(SV *in_pub_ec_key,  SV *out_ec_key ,SV *out_ec_pub_key ){

    int keySize=200 , i=0;
    BIO  *out = NULL , *out_pub= NULL, *in_pub=NULL ,*tmp =NULL ;
    long r=0, len=0;
    unsigned char outkey[keySize] ;
    unsigned char *outbuf=NULL;
    EC_GROUP *group = NULL;
    EC_KEY 	*ec_pubkey = NULL , * eckey = NULL , *testkey =NULL ;
    char *c_ec_pub_key =NULL;
    char *c_ec_key =NULL;
    unsigned char * sessionkey=NULL;
    SV *key = NULL;

    //read supplied public key   
    in_pub = BIO_new(BIO_s_mem());
    r =  BIO_puts(in_pub, SvPV(in_pub_ec_key, PL_na));
    ec_pubkey = PEM_read_bio_EC_PUBKEY(in_pub, NULL,NULL,NULL);

    if(ec_pubkey == NULL)
    {
	if (ec_pubkey) EC_KEY_free(ec_pubkey);
        croak("missing or invalid public key");

    }
    
    group = EC_KEY_get0_group(ec_pubkey);
    if(group == NULL)
    {
        if (ec_pubkey) EC_KEY_free(ec_pubkey);
        croak("failed to get key group from supplied public key");
    }    

    tmp = BIO_new(BIO_s_mem());
    len = BIO_puts(tmp,  SvPV(out_ec_key, PL_na));

     //if there is no keypair supplied via out_ec_key, create a new keypair 
     if(len <= 0)
     {
	//generate new key 
	eckey = EC_KEY_new();
	//Set same group as used in the supplied public key
	if(! EC_KEY_set_group(eckey, group)){
		croak("can't set group from supplied public key");
	}

	if(!EC_KEY_generate_key(eckey))
	{
	    //if there was an error generating the key free the key memory
	    if (eckey) EC_KEY_free(eckey);
            if (ec_pubkey) EC_KEY_free(ec_pubkey);
	    if (out) BIO_free(out);
	    if (out_pub) BIO_free(out_pub);
	    if (tmp) BIO_free(tmp);

            croak("error key generation failed");
	}

      }else{
	eckey = PEM_read_bio_ECPrivateKey(tmp, NULL,NULL,NULL);

	    if(eckey == NULL)
	    {
		if (eckey) EC_KEY_free(eckey);
                if (ec_pubkey) EC_KEY_free(ec_pubkey);
	        if (out) BIO_free(out);
	        if (out_pub) BIO_free(out_pub);
	        if (tmp) BIO_free(tmp);

		croak("missing private key");
	    }
      }

     	out = BIO_new(BIO_s_mem());
     	r = PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL); 	
     	len = BIO_get_mem_data(out, NULL );

     	c_ec_key = (char *) malloc (len+1);
     	r = BIO_read(out, c_ec_key,len);
     	(c_ec_key)[len]= '\0';

        sv_setpvn(out_ec_key,c_ec_key,len);

	out_pub=BIO_new(BIO_s_mem());
	r = PEM_write_bio_EC_PUBKEY(out_pub, eckey,NULL,NULL, 0,NULL, NULL);
	len = BIO_get_mem_data(out_pub,NULL);
	c_ec_pub_key = (char *) malloc (len+1);
	r = BIO_read(out_pub, c_ec_pub_key, len);
	(c_ec_pub_key)[len]= '\0';
	sv_setpvn(out_ec_pub_key,c_ec_pub_key,len);
	
	int n = ECDH_compute_key(outkey, keySize, EC_KEY_get0_public_key(ec_pubkey), eckey, NULL );
	printf("n = %d \n", n);
	outkey[n]='\0';

	key = newSVpvn(outkey ,n);
	
	//	if (outkey) free(outkey);
		if (c_ec_key) free(c_ec_key);
		if (c_ec_pub_key) free(c_ec_pub_key);
		if (eckey) EC_KEY_free(eckey);
		if (ec_pubkey) EC_KEY_free(ec_pubkey);
		if (out) BIO_free(out);
		if (out_pub) BIO_free(out_pub);
		if (tmp) BIO_free(tmp);

	return key;
}

__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Crypt::ECDH - Perl extension for elliptic curve Diffi-Hellmann key exchange 

=head1 SYNOPSIS

  use Crypt::ECDH;
  
=head1 DESCRIPTION

This impementation uses Inline::C to implemnt openSSL ECDH functionality. in Addition it also gives you a interface to create EC Keys and to extract a public key from an existing key pair. 

=head2 EXPORT

Crypt::ECDH::new_ec_keypair(nid);

Crypt::ECDH::get_ec_pub_key()

Crypt::ECDH::get_ecdh_key()

=head2 new_ec_keypair(nid);

This function requires a valid openSSL NID to create a ECKey pair. The created key will be retured in PEM format.
  
 eg: Crypt::ECDH::new_ec_keypair(708); //to create a EC keypair using the secp160k1 domain parameters

Some openSSL EC NID's : 

#define SN_secp112r1		"secp112r1"
#define NID_secp112r1		704
#define OBJ_secp112r1		OBJ_secg_ellipticCurve,6L

#define SN_secp112r2		"secp112r2"
#define NID_secp112r2		705
#define OBJ_secp112r2		OBJ_secg_ellipticCurve,7L

#define SN_secp128r1		"secp128r1"
#define NID_secp128r1		706
#define OBJ_secp128r1		OBJ_secg_ellipticCurve,28L

#define SN_secp128r2		"secp128r2"
#define NID_secp128r2		707
#define OBJ_secp128r2		OBJ_secg_ellipticCurve,29L

#define SN_secp160k1		"secp160k1"
#define NID_secp160k1		708
#define OBJ_secp160k1		OBJ_secg_ellipticCurve,9L

#define SN_secp160r1		"secp160r1"
#define NID_secp160r1		709
#define OBJ_secp160r1		OBJ_secg_ellipticCurve,8L

#define SN_secp160r2		"secp160r2"
#define NID_secp160r2		710
#define OBJ_secp160r2		OBJ_secg_ellipticCurve,30L

#define SN_secp192k1		"secp192k1"
#define NID_secp192k1		711
#define OBJ_secp192k1		OBJ_secg_ellipticCurve,31L

#define SN_secp224k1		"secp224k1"
#define NID_secp224k1		712
#define OBJ_secp224k1		OBJ_secg_ellipticCurve,32L

#define SN_secp224r1		"secp224r1"
#define NID_secp224r1		713
#define OBJ_secp224r1		OBJ_secg_ellipticCurve,33L

#define SN_secp256k1		"secp256k1"
#define NID_secp256k1		714
#define OBJ_secp256k1		OBJ_secg_ellipticCurve,10L

#define SN_secp384r1		"secp384r1"
#define NID_secp384r1		715
#define OBJ_secp384r1		OBJ_secg_ellipticCurve,34L

#define SN_secp521r1		"secp521r1"
#define NID_secp521r1		716
#define OBJ_secp521r1		OBJ_secg_ellipticCurve,35L

#define SN_sect113r1		"sect113r1"
#define NID_sect113r1		717
#define OBJ_sect113r1		OBJ_secg_ellipticCurve,4L

#define SN_sect113r2		"sect113r2"
#define NID_sect113r2		718
#define OBJ_sect113r2		OBJ_secg_ellipticCurve,5L

#define SN_sect131r1		"sect131r1"
#define NID_sect131r1		719
#define OBJ_sect131r1		OBJ_secg_ellipticCurve,22L

#define SN_sect131r2		"sect131r2"
#define NID_sect131r2		720
#define OBJ_sect131r2		OBJ_secg_ellipticCurve,23L

#define SN_sect163k1		"sect163k1"
#define NID_sect163k1		721
#define OBJ_sect163k1		OBJ_secg_ellipticCurve,1L

#define SN_sect163r1		"sect163r1"
#define NID_sect163r1		722
#define OBJ_sect163r1		OBJ_secg_ellipticCurve,2L

#define SN_sect163r2		"sect163r2"
#define NID_sect163r2		723
#define OBJ_sect163r2		OBJ_secg_ellipticCurve,15L

#define SN_sect193r1		"sect193r1"
#define NID_sect193r1		724
#define OBJ_sect193r1		OBJ_secg_ellipticCurve,24L

#define SN_sect193r2		"sect193r2"
#define NID_sect193r2		725
#define OBJ_sect193r2		OBJ_secg_ellipticCurve,25L

#define SN_sect233k1		"sect233k1"
#define NID_sect233k1		726
#define OBJ_sect233k1		OBJ_secg_ellipticCurve,26L

#define SN_sect233r1		"sect233r1"
#define NID_sect233r1		727
#define OBJ_sect233r1		OBJ_secg_ellipticCurve,27L

#define SN_sect239k1		"sect239k1"
#define NID_sect239k1		728
#define OBJ_sect239k1		OBJ_secg_ellipticCurve,3L

#define SN_sect283k1		"sect283k1"
#define NID_sect283k1		729
#define OBJ_sect283k1		OBJ_secg_ellipticCurve,16L

#define SN_sect283r1		"sect283r1"
#define NID_sect283r1		730
#define OBJ_sect283r1		OBJ_secg_ellipticCurve,17L

#define SN_sect409k1		"sect409k1"
#define NID_sect409k1		731
#define OBJ_sect409k1		OBJ_secg_ellipticCurve,36L

#define SN_sect409r1		"sect409r1"
#define NID_sect409r1		732
#define OBJ_sect409r1		OBJ_secg_ellipticCurve,37L

#define SN_sect571k1		"sect571k1"
#define NID_sect571k1		733
#define OBJ_sect571k1		OBJ_secg_ellipticCurve,38L

#define SN_sect571r1		"sect571r1"
#define NID_sect571r1		734
#define OBJ_sect571r1		OBJ_secg_ellipticCurve,39L

=head2 Crypt::ECDH::get_ec_pub_key(PEM_ECKey)

Get ec pub key extracts the public key from a EC Key that is handed to the function in PEM format. The return value is a PEM encoded public key. 

=head2 Crypt::ECDH::get_ecdh_key(in_pub_ec_key, ec_key )

This function takes in a public EC key in PEM format. 

It will either compute a new keypair with the same EC parameters as the supplied public key. And generate a ECDH key. 

Or it can use an exisiting key pair if it is supplied in ec_key and generate a ECDH key. 

The result is a hash with the structure:
 $returned = (
    'PEMECKey' => 'PEM encoded EC Key, that was supplied or newly generated',
    'PEMECPubKey' => 'The PEM encoded EC public key to the privatekey above',
    'ECDHKey' => 'Computed ECDH key as binary data that can be used as source for a hash function e.g. to generate a session secret key that is easy to use'
  ) 

=head1 SEE ALSO

See also at openSSL's documetation about elliptic curves. 
A full list of the NID's listed above can be found under "openssl/crypto/objects/obj_mac.h".

OpenSSL ECDH 

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

rad1us, <lt>arkadius.litwinczuk@gmail.com<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by rad1us

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
