.. cyrusman:: pop3test(1)

.. _imap-admin-usercommands-pop3test:

============
**pop3test**
============

Interactive POP3 test program.

Synopsis
========

.. parsed-literal::

    **pop3test** [ **-t** *keyfile* ] [ **-p** *port* ] [ **-m** *mechanism* ] [ **-a** *userid* ]
        [ **-u** *userid* ] [ **-k** *num* ] [ **-l** *num* ] [ **-r** *realm* ] [ **-f** *file* ]
        [ **-n** *num* ] [ **-s** ] [ **-c** ] [ **-i** ] [ **-v** ] [ **-o** *option*\ =\ *value* ] *hostname*

Description
===========

This is actually installed as a hard linked copy of :cyrusman:`imtest(1)`.

**pop3test** is a utility that allows you to authenticate to a
POP3 server and interactively issue commands to it. Once
authenticated you may issue any POP3 command by simply typing it in.
It is capable of multiple SASL authentication mechanisms and handles
encryption layers transparently. This utility is often used for testing
the operation of an pop3 server. Also those developing POP3 clients
find it useful.

Options
=======

.. program:: pop3test

.. option:: -t  keyfile

    Enable TLS.  *keyfile* contains the TLS public and private keys.
    Specify **""** to negotiate a TLS encryption layer but not use TLS
    authentication.

.. option:: -p  port

    Port to connect to. If left off this defaults to **pop3** as
    defined in ``/etc/services``.

.. option:: -m  mechanism

    Force **pop3test** to use *mechanism* for authentication. If not
    specified, the strongest authentication mechanism supported by the
    server is chosen.  Specify *login* to use the LOGIN command instead
    of AUTHENTICATE.

.. option:: -a  userid

    Userid to use for authentication; defaults to the current user.
    This is the userid whose password or credentials will be presented
    to the server for verification.

.. option:: -u  userid

    Userid to use for authorization; defaults to the current user.
    This is the userid whose identity will be assumed after
    authentication.

    .. Note::
        This is only used with SASL mechanisms that allow proxying
        (e.g. PLAIN, DIGEST-MD5).

.. option:: -k  num

    Minimum protection layer required.

.. option:: -l  num

    Maximum protection layer to use (**0**\ =none; **1**\ =integrity;
    etc).  For example if you are using the KERBEROS_V4 authentication
    mechanism specifying **0** will force imtest to not use any layer
    and specifying **1** will force it to use the integrity layer.  By
    default the maximum supported protection layer will be used.

.. option:: -r  realm

    Specify the *realm* to use. Certain authentication mechanisms
    (e.g. DIGEST-MD5) may require one to specify the realm.

.. option:: -f  file

    Pipe *file* into connection after authentication.

.. option:: -n  num

    Number of authentication attempts; default = 1.  The client will
    attempt to do SSL/TLS session reuse and/or fast reauth
    (e.g. DIGEST-MD5), if possible.

.. option:: -s

    Enable POP3 over SSL (pop3s).

.. option:: -c

    Enable challenge prompt callbacks.  This will cause the OTP
    mechanism to ask for the the one-time password instead of the
    secret pass-phrase (library generates the correct response).

.. option:: -i

    Don't send an initial client response for SASL mechanisms, even if
    the protocol supports it.

.. option:: -v

    Verbose. Print out more information than usual.

.. option:: -o  option=value

    Set the SASL *option* to *value*.

Examples
========

See Also
========

:cyrusman:`pop3d(8)`
