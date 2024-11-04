# IdGen

(C) 2024 David Cesarino de Sousa <1624159+davidcesarino@users.noreply.github.com>

Generates keys and certificates based on a JSON file.

## Basic usage

```
idgen [-h] [-l] [-a] [-v {error,warning,info,debug}] 
      config_file output_dir
```

### Options

`-h`, `--help`: shows this help message and exit.

`-l`, `--license`: show program license and exit.

`-a`, `--about`: show version and exit.

`-v {error,warning,info,debug}`: sets log verbosity; defaults to warning.

### Positional parameters

If no options are provided, then these parameters are mandatory.

`config_file`: describes the keys and certificates in JSON format. See the 
section _“Json file format”_ below.

`output_dir`: the output folder, as path. The trailing `/` is optional and
will be automatically included if missing.

## JSON file format

See the included file `example.json` for a complete example. Below is a 
list of all supported fields.

### Root level

These are list entries for all respective elements defined:

`keysets`

`certificates`

### 1. Keysets

A keyset is a collection of at most 2 independent keys: RSA and Ed25519.
Each keyset admits the following entries:

`name`

Identifier string for this keyset.

`rsa`

Definitions for the RSA key.

`ed25519`

Definitions for the ED25519 key.

#### RSA and ED25519 keys

`id`

A positive, non-zero, integer identifier, that is unique for the entire
configuration file (including both keys and certificates), thus uniquely 
identifying this key.

`size` _(RSA-only)_

An integer corresponding to the key length in bytes. Anything less than 
2048 is ignored and is replaced by 2048.

`secret`

The password for encrypting the key. If empty, the private 
key will be unencrypted.

`output`

A list of all format variations that will be written to the disk. Leave
it empty (`[]`) to not write the key to the disk. Available values are:

- `"pkcs8"`: private PKCS8.
- `"private_ssh"`: private OpenSSH.
- `"pkcs1"`: public PKCS1.
- `"public_ssh"`: public OpenSSH.

> ## ⚠️
> 
> - If other strings are included, the behavior may be undefined.
> - If no format is included, no key will be output to disk. 
>   It is generally recommended, therefore, that at least one private 
>   format be included here if you are not loading the key from disk, to
>   preserve the generated key.

`file`

Defines keys already available in the filesystem so you can load them
instead of generating the keys with the program. Subentries:

`pkcs8`: the path to the PKCS8 key file. It _**must**_ correspond to a 
private key in the PKCS8 format.

`private_ssh`: the path to the private SSH key file. It _**must**_
correspond to a private key in the OpenSSH format.

`use`: Identifies which file to load. Available values:
  - Empty (`""`): the program will generate the key, not loading it from disk.
  - `"pkcs8"`: loads the key from the `pkcs8` path defined above.
  - `"private_ssh"`: loads the key from the `private_ssh` path defined above.

> ## 💡
>
> You can define both the `pkcs8` and `private_ssh` paths and set the
> `use` entry to easily switch between both or deactivate loading the key
> from disk entirely.

### 2. Certificates

`id`

A positive, non-zero, unique integer identifier. As stated before, it
must be unique not only between certificates but also between certificates
and keys as well.

`key`

The id identifying the key to use to sign the certificate. It _**must**_
correspond to a previously defined key.

`name`

Identifier string for the certificate.

`file`

When not empty, loads the certificate from this path instead of generating, 
ignoring `days_valid`, `root`, `sign_other`, `max_subordinates` and 
`subject` fields.

`days_valid`

A positive integer (it can be zero) that identifies the number of days
for the certificate to be valid, expiring at the last second of the day.

> ## ⚠️
>
> All time references are UTC based.

`root`

The id identifying the parent certificate. It can be any integer number,
as setting it to zero or less—an invalid id—signals that it is the 
root certificate itself of whatever chain the certificate is part of.

`sign_other`

A boolean telling wether this certificate can be used to sign other 
certificates.

> ## ⚠️
>
> Note that a certificate without a parent (i.e., a root) does not 
> necessarily need to have `sign_other` set to `true`. It is perfectly 
> valid for a root certificate to stand by itself, without being able to
> sign other certificates, although that is, of course, a _very_ bad 
> practice that is highly _not_ recommended.

`max_subordinates`

The path length for this certificate, i.e., the maximum depth of the chain
of children certificates under this one. Use it to control the maximum 
depth of your certificate chains.

> ## 💡
> - If you do not want to restrict the chain depth, set this value to `-1`.
> - It is usual for root certificates to have this value set to `-1`, and 
>   leaf (end-chain) certificates set to `0`. Intermediary certificates
>   vary widely and the correct number depends much on your company 
>   structure.

`subject`

A subset of the [ITU T-REC-X.520 Name](https://www.itu.int/rec/T-REC-X.520) 
attributes. Subentries:

- `c`: country.
- `st`: province or state.
- `l`: locality, city or municipality.
- `o`: your organization.
- `ou`: organization unit.
- `cn`: common name.
- `emailAddress`: the e-mail contact for the person responsible for this
                  certificate.
