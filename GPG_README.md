## Import the keys

I have two keys, a personal one and a project one, on *keys.openpgp.org*.
At the end of this doc is a pic of me holding up these keys handwritten
on a notepad. If you need more trust than that, get in touch.

     % gpg --keyserver keys.openpgp.org --recv-keys 75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041 867D53B08E433DF401A06EF49A9C0FE7F64876BF

If you trust these signatures, sign them with your own key. This way you
avoid a local warning about verifying files with untrusted keys. Likewise,
if you do not trust these keys and want to tolerate the warning, don't
sign them:

     % gpg --sign-key 867D53B08E433DF401A06EF49A9C0FE7F64876BF
     % gpg --sign-key 75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041

## Verify the database

I've started to sign lib/CPAN/Audit/DB.pm with [a GPG key I made for
this module](https://keys.openpgp.org/vks/v1/by-fingerprint/75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041).
The file *lib/CPAN/Audit/DB.pm.gpg* is the detached signature for *lib/CPAN/Audit/DB.pm*.

	% gpg --verify lib/CPAN/Audit/DB.pm.gpg lib/CPAN/Audit/DB.pm

You may get a warning like:

> gpg: WARNING: This key is not certified with a trusted signature!

That means you didn't sign the keys, so your local GPG is reminding
you that you don't trust them even if it can still verify the signatures.

## Help others trust CPAN::Audit

We can enhance this trust for *lib/CPAN/Audit/DB.pm* by including more
trust in the key that signs that data. You can do this by signing the
key to say that you trust it.

You can sign my personal and my CPAN::Audit key with your key:

     % gpg --keyserver keys.openpgp.org --recv-keys 75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041 867D53B08E433DF401A06EF49A9C0FE7F64876BF
     % gpg --sign-key 867D53B08E433DF401A06EF49A9C0FE7F64876BF
     % gpg --sign-key 75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041
     % gpg --output ~/pobox.signed.gpg --export --armor 867D53B08E433DF401A06EF49A9C0FE7F64876BF
     % gpg --output ~/bdfoy.signed.gpg --export --armor 75AAB42CBA0D7F37F0D6886DF83F8D5E878B6041

Then send those output files back to me at *briandfoy@pobox.com*, or
some other channel that you'd like to use. I will import them into my
keyring and re-export my key to the keyserver so other people will see
that you signed the key.

## Github Actions

When I push to Github, the "gpg" workflow checks that the files signed
in the repo have the right signatures.

## The selfie

Here's a selfie with me holding up the two key fingerprints (google
images of me to see if you think this is the same person). For the
more cautious (not a bad thing here), we can arrange a way to verify
that these keys belong to me and you are sending them to the right
place.

![](images/briandfoy-gpg-key-selfie.jpeg)
