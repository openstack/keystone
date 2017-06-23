====================
Certificates for PKI
====================

PKI stands for Public Key Infrastructure. Tokens are documents,
cryptographically signed using the X509 standard. In order to work
correctly token generation requires a public/private key pair. The
public key must be signed in an X509 certificate, and the certificate
used to sign it must be available as a Certificate Authority (CA)
certificate. These files can be generated either using the
:command:`keystone-manage` utility, or externally generated. The files need to
be in the locations specified by the top level Identity service
configuration file ``/etc/keystone/keystone.conf`` as specified in the
above section. Additionally, the private key should only be readable by
the system user that will run the Identity service.


.. warning::

   The certificates can be world readable, but the private key cannot
   be. The private key should only be readable by the account that is
   going to sign tokens. When generating files with the
   :command:`keystone-manage pki_setup` command, your best option is to run
   as the pki user. If you run :command:`keystone-manage` as root, you can
   append ``--keystone-user`` and ``--keystone-group`` parameters
   to set the user name and group keystone is going to run under.

The values that specify where to read the certificates are under the
``[signing]`` section of the configuration file. The configuration
values are:

- ``certfile``
    Location of certificate used to verify tokens. Default is
    ``/etc/keystone/ssl/certs/signing_cert.pem``.

-  ``keyfile``
    Location of private key used to sign tokens. Default is
    ``/etc/keystone/ssl/private/signing_key.pem``.

- ``ca_certs``
    Location of certificate for the authority that issued
    the above certificate. Default is
    ``/etc/keystone/ssl/certs/ca.pem``.

- ``ca_key``
    Location of the private key used by the CA. Default is
    ``/etc/keystone/ssl/private/cakey.pem``.

- ``key_size``
    Default is ``2048``.

- ``valid_days``
    Default is ``3650``.

- ``cert_subject``
    Certificate subject (auto generated certificate) for token signing.
    Default is ``/C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com``.

When generating certificates with the :command:`keystone-manage pki_setup`
command, the ``ca_key``, ``key_size``, and ``valid_days`` configuration
options are used.

If the :command:`keystone-manage pki_setup` command is not used to generate
certificates, or you are providing your own certificates, these values
do not need to be set.

If ``provider=keystone.token.providers.uuid.Provider`` in the
``[token]`` section of the keystone configuration file, a typical token
looks like ``53f7f6ef0cc344b5be706bcc8b1479e1``. If
``provider=keystone.token.providers.pki.Provider``, a typical token is a
much longer string, such as::

    MIIKtgYJKoZIhvcNAQcCoIIKpzCCCqMCAQExCTAHBgUrDgMCGjCCCY8GCSqGSIb3DQEHAaCCCYAEggl8eyJhY2Nlc3MiOiB7InRva2VuIjogeyJpc3N1ZWRfYXQiOiAiMjAxMy0wNS0z
    MFQxNTo1MjowNi43MzMxOTgiLCAiZXhwaXJlcyI6ICIyMDEzLTA1LTMxVDE1OjUyOjA2WiIsICJpZCI6ICJwbGFjZWhvbGRlciIsICJ0ZW5hbnQiOiB7ImRlc2NyaXB0aW9uIjogbnVs
    bCwgImVuYWJsZWQiOiB0cnVlLCAiaWQiOiAiYzJjNTliNGQzZDI4NGQ4ZmEwOWYxNjljYjE4MDBlMDYiLCAibmFtZSI6ICJkZW1vIn19LCAic2VydmljZUNhdGFsb2ciOiBbeyJlbmRw
    b2ludHMiOiBbeyJhZG1pblVSTCI6ICJodHRwOi8vMTkyLjE2OC4yNy4xMDA6ODc3NC92Mi9jMmM1OWI0ZDNkMjg0ZDhmYTA5ZjE2OWNiMTgwMGUwNiIsICJyZWdpb24iOiAiUmVnaW9u
    T25lIiwgImludGVybmFsVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDo4Nzc0L3YyL2MyYzU5YjRkM2QyODRkOGZhMDlmMTY5Y2IxODAwZTA2IiwgImlkIjogIjFmYjMzYmM5M2Y5
    ODRhNGNhZTk3MmViNzcwOTgzZTJlIiwgInB1YmxpY1VSTCI6ICJodHRwOi8vMTkyLjE2OC4yNy4xMDA6ODc3NC92Mi9jMmM1OWI0ZDNkMjg0ZDhmYTA5ZjE2OWNiMTgwMGUwNiJ9XSwg
    ImVuZHBvaW50c19saW5rcyI6IFtdLCAidHlwZSI6ICJjb21wdXRlIiwgIm5hbWUiOiAibm92YSJ9LCB7ImVuZHBvaW50cyI6IFt7ImFkbWluVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3
    LjEwMDozMzMzIiwgInJlZ2lvbiI6ICJSZWdpb25PbmUiLCAiaW50ZXJuYWxVUkwiOiAiaHR0cDovLzE5Mi4xNjguMjcuMTAwOjMzMzMiLCAiaWQiOiAiN2JjMThjYzk1NWFiNDNkYjhm
    MGU2YWNlNDU4NjZmMzAiLCAicHVibGljVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDozMzMzIn1dLCAiZW5kcG9pbnRzX2xpbmtzIjogW10sICJ0eXBlIjogInMzIiwgIm5hbWUi
    OiAiczMifSwgeyJlbmRwb2ludHMiOiBbeyJhZG1pblVSTCI6ICJodHRwOi8vMTkyLjE2OC4yNy4xMDA6OTI5MiIsICJyZWdpb24iOiAiUmVnaW9uT25lIiwgImludGVybmFsVVJMIjog
    Imh0dHA6Ly8xOTIuMTY4LjI3LjEwMDo5MjkyIiwgImlkIjogIjczODQzNTJhNTQ0MjQ1NzVhM2NkOTVkN2E0YzNjZGY1IiwgInB1YmxpY1VSTCI6ICJodHRwOi8vMTkyLjE2OC4yNy4x
    MDA6OTI5MiJ9XSwgImVuZHBvaW50c19saW5rcyI6IFtdLCAidHlwZSI6ICJpbWFnZSIsICJuYW1lIjogImdsYW5jZSJ9LCB7ImVuZHBvaW50cyI6IFt7ImFkbWluVVJMIjogImh0dHA6
    Ly8xOTIuMTY4LjI3LjEwMDo4Nzc2L3YxL2MyYzU5YjRkM2QyODRkOGZhMDlmMTY5Y2IxODAwZTA2IiwgInJlZ2lvbiI6ICJSZWdpb25PbmUiLCAiaW50ZXJuYWxVUkwiOiAiaHR0cDov
    LzE5Mi4xNjguMjcuMTAwOjg3NzYvdjEvYzJjNTliNGQzZDI4NGQ4ZmEwOWYxNjljYjE4MDBlMDYiLCAiaWQiOiAiMzQ3ZWQ2ZThjMjkxNGU1MGFlMmJiNjA2YWQxNDdjNTQiLCAicHVi
    bGljVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDo4Nzc2L3YxL2MyYzU5YjRkM2QyODRkOGZhMDlmMTY5Y2IxODAwZTA2In1dLCAiZW5kcG9pbnRzX2xpbmtzIjogW10sICJ0eXBl
    IjogInZvbHVtZSIsICJuYW1lIjogImNpbmRlciJ9LCB7ImVuZHBvaW50cyI6IFt7ImFkbWluVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDo4NzczL3NlcnZpY2VzL0FkbWluIiwg
    InJlZ2lvbiI6ICJSZWdpb25PbmUiLCAiaW50ZXJuYWxVUkwiOiAiaHR0cDovLzE5Mi4xNjguMjcuMTAwOjg3NzMvc2VydmljZXMvQ2xvdWQiLCAiaWQiOiAiMmIwZGMyYjNlY2U4NGJj
    YWE1NDAzMDMzNzI5YzY3MjIiLCAicHVibGljVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDo4NzczL3NlcnZpY2VzL0Nsb3VkIn1dLCAiZW5kcG9pbnRzX2xpbmtzIjogW10sICJ0
    eXBlIjogImVjMiIsICJuYW1lIjogImVjMiJ9LCB7ImVuZHBvaW50cyI6IFt7ImFkbWluVVJMIjogImh0dHA6Ly8xOTIuMTY4LjI3LjEwMDozNTM1Ny92Mi4wIiwgInJlZ2lvbiI6ICJS
    ZWdpb25PbmUiLCAiaW50ZXJuYWxVUkwiOiAiaHR0cDovLzE5Mi4xNjguMjcuMTAwOjUwMDAvdjIuMCIsICJpZCI6ICJiNTY2Y2JlZjA2NjQ0ZmY2OWMyOTMxNzY2Yjc5MTIyOSIsICJw
    dWJsaWNVUkwiOiAiaHR0cDovLzE5Mi4xNjguMjcuMTAwOjUwMDAvdjIuMCJ9XSwgImVuZHBvaW50c19saW5rcyI6IFtdLCAidHlwZSI6ICJpZGVudGl0eSIsICJuYW1lIjogImtleXN0
    b25lIn1dLCAidXNlciI6IHsidXNlcm5hbWUiOiAiZGVtbyIsICJyb2xlc19saW5rcyI6IFtdLCAiaWQiOiAiZTVhMTM3NGE4YTRmNDI4NWIzYWQ3MzQ1MWU2MDY4YjEiLCAicm9sZXMi
    OiBbeyJuYW1lIjogImFub3RoZXJyb2xlIn0sIHsibmFtZSI6ICJNZW1iZXIifV0sICJuYW1lIjogImRlbW8ifSwgIm1ldGFkYXRhIjogeyJpc19hZG1pbiI6IDAsICJyb2xlcyI6IFsi
    YWRiODM3NDVkYzQzNGJhMzk5ODllNjBjOTIzYWZhMjgiLCAiMzM2ZTFiNjE1N2Y3NGFmZGJhNWUwYTYwMWUwNjM5MmYiXX19fTGB-zCB-AIBATBcMFcxCzAJBgNVBAYTAlVTMQ4wDAYD
    VQQIEwVVbnNldDEOMAwGA1UEBxMFVW5zZXQxDjAMBgNVBAoTBVVuc2V0MRgwFgYDVQQDEw93d3cuZXhhbXBsZS5jb20CAQEwBwYFKw4DAhowDQYJKoZIhvcNAQEBBQAEgYCAHLpsEs2R
    nouriuiCgFayIqCssK3SVdhOMINiuJtqv0sE-wBDFiEj-Prcudqlz-n+6q7VgV4mwMPszz39-rwp+P5l4AjrJasUm7FrO-4l02tPLaaZXU1gBQ1jUG5e5aL5jPDP08HbCWuX6wr-QQQB
    SrWY8lF3HrTcJT23sZIleg==

Sign certificate issued by external CA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can use a signing certificate issued by an external CA instead of
generated by :command:`keystone-manage`. However, a certificate issued by an
external CA must satisfy the following conditions:

- All certificate and key files must be in Privacy Enhanced Mail (PEM)
  format

- Private key files must not be protected by a password

When using a signing certificate issued by an external CA, you do not
need to specify ``key_size``, ``valid_days``, and ``ca_password`` as
they will be ignored.

The basic workflow for using a signing certificate issued by an external
CA involves:

#. Request Signing Certificate from External CA

#. Convert certificate and private key to PEM if needed

#. Install External Signing Certificate

Request a signing certificate from an external CA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One way to request a signing certificate from an external CA is to first
generate a PKCS #10 Certificate Request Syntax (CRS) using OpenSSL CLI.

Create a certificate request configuration file. For example, create the
``cert_req.conf`` file, as follows:

.. code-block:: ini

   [ req ]
   default_bits            = 4096
   default_keyfile         = keystonekey.pem
   default_md              = sha256

   prompt                  = no
   distinguished_name      = distinguished_name

   [ distinguished_name ]
   countryName             = US
   stateOrProvinceName     = CA
   localityName            = Sunnyvale
   organizationName        = OpenStack
   organizationalUnitName  = Keystone
   commonName              = Keystone Signing
   emailAddress            = keystone@openstack.org

Then generate a CRS with OpenSSL CLI. **Do not encrypt the generated
private key. You must use the -nodes option.**

For example:

.. code-block:: console

   $ openssl req -newkey rsa:1024 -keyout signing_key.pem -keyform PEM \
     -out signing_cert_req.pem -outform PEM -config cert_req.conf -nodes

If everything is successful, you should end up with
``signing_cert_req.pem`` and ``signing_key.pem``. Send
``signing_cert_req.pem`` to your CA to request a token signing certificate
and make sure to ask the certificate to be in PEM format. Also, make sure your
trusted CA certificate chain is also in PEM format.

Install an external signing certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Assuming you have the following already:

- ``signing_cert.pem``
    (Keystone token) signing certificate in PEM format

- ``signing_key.pem``
    Corresponding (non-encrypted) private key in PEM format

- ``cacert.pem``
    Trust CA certificate chain in PEM format

Copy the above to your certificate directory. For example:

.. code-block:: console

   # mkdir -p /etc/keystone/ssl/certs
   # cp signing_cert.pem /etc/keystone/ssl/certs/
   # cp signing_key.pem /etc/keystone/ssl/certs/
   # cp cacert.pem /etc/keystone/ssl/certs/
   # chmod -R 700 /etc/keystone/ssl/certs

.. note::

   Make sure the certificate directory is only accessible by root.

.. note::

   The procedure of copying the key and cert files may be improved if
   done after first running :command:`keystone-manage pki_setup` since this
   command also creates other needed files, such as the ``index.txt``
   and ``serial`` files.

   Also, when copying the necessary files to a different server for
   replicating the functionality, the entire directory of files is
   needed, not just the key and cert files.

If your certificate directory path is different from the default
``/etc/keystone/ssl/certs``, make sure it is reflected in the
``[signing]`` section of the configuration file.

Switching out expired signing certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following procedure details how to switch out expired signing
certificates with no cloud outages.

#. Generate a new signing key.

#. Generate a new certificate request.

#. Sign the new certificate with the existing CA to generate a new
   ``signing_cert``.

#. Append the new ``signing_cert`` to the old ``signing_cert``. Ensure the
   old certificate is in the file first.

#. Remove all signing certificates from all your hosts to force OpenStack
   Compute to download the new ``signing_cert``.

#. Replace the old signing key with the new signing key. Move the new
   signing certificate above the old certificate in the ``signing_cert``
   file.

#. After the old certificate reads as expired, you can safely remove the
   old signing certificate from the file.
