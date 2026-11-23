# Model integrity

This page describes what the `model` collector records for model files, which other
files it binds to them by digest, and how an operator signature policy verifies
model weights. Collection is static: no model file is loaded, no template is
rendered and no repository code is imported.

## Model files and references

The collector inventories every file whose name has one of these suffixes:
`.safetensors`, `.onnx`, `.gguf`, `.ggml`, `.h5`, `.hdf5`, `.keras`, `.tflite`,
`.mlmodel`, `.pte`, and the pickle family `.pkl`, `.pickle`, `.pck`, `.dill`,
`.cloudpickle`, `.pt`, `.pth`, `.bin`, `.joblib`, `.ckpt` and `.pdparams`. A
pickle-family name inside one or two archive or compression suffixes (`.tar`, `.gz`,
`.bz2`, `.xz`, `.lzma`, `.zst`, `.z`, `.lz4`, `.zip`), such as `checkpoint.pth.tar`,
`model.pkl.gz`, joblib's `clf.joblib.z` and `clf.joblib.lz4`, or pandas'
`frame.pkl.zip` and `frame.pkl.tar.gz`, counts as pickle family too, and such a file
is `unsafe-code-execution` whatever it holds unless it is empty, since its content is
not decompressed. A third wrapper suffix, which no loader unwraps by name, does not.
TensorFlow graphs named
`saved_model.pb` or `saved_model.pbtxt` are collected; other `.pb` files are not.

A file that no name above rates is inventoried by its content when it is named
`.npy`, `.npz` or `.dat`, or has any name below a directory named `model`, `models`,
`weights`, `checkpoint` or `checkpoints`. A file named as the configuration,
tokenizer and chat template files that a model directory's readers open are, such
as `config.json` or `tokenizer.json`, and Python and Jinja sources are not checked
this way. Such a file is a component when its content is rated
`unsafe-code-execution` by the checks in the table below, or when the content is a
NumPy array, a ZIP archive or a pickle that those checks' bounds left unread, which
is rated `unknown`.

A pickle is rated by what `pickle.load` does with it. The check reads the first
64 KiB as `pickle.load` reads them from `io.BytesIO`, in a loop, as `torch.load` reads
the three header pickles of `torch.save`'s legacy format before the main one: once as
the C unpickler and once as the pure-Python one, opcode by opcode, with the same
frame handling, stack, MARK and memo rules and the same errors, for at most 4,096
opcodes and 64 MARKs over all the pickles read. Where the unpicklers of CPython 3.11
to 3.14 differ, it takes every reading one of them takes: `INT` and `LONG` text in
base 0, as up to 3.13 (`I0x1f`), and in base 10, as from 3.14 (`I08`), and, for the C
unpickler of 3.11 and 3.12, a read past the end of a frame, which goes on from where
the pickle stands or from the frame's end. It also takes every reading that a loader's
`encoding` gives a `STRING`, `BINSTRING` or `SHORT_BINSTRING` with a byte over 0x7f,
which the default `"ASCII"` fails: `torch.load` passes `"utf-8"`, `np.load` and
`pandas.read_pickle` `"latin1"`, and `"bytes"` keeps the bytes, which `READONLY_BUFFER`
takes. A call that one supported version or encoding reaches is rated whatever version
runs the scan. It never imports, calls or builds an
object: what `find_class` returns is a placeholder that stands for any attribute of a
module, a class or a function as well as `os.environ`, `sys.path` or
`builtins.__dict__`. `find_class` imports the module before it looks the name up, and
`importlib` imports a file of any name, such as `ev-il.py` or `evil x.py`, so only a
module that no finder can name fails as the import does: an empty one, one with a NUL,
or one with a `/` in a dotted part. A pickle
ends where `pickle.load` would stop: at STOP, where the next one starts, or at the
first error, such as a byte that is no opcode, PROTO above 5, a stack underflow, a
MARK that is missing, a read of a memo slot never stored, an unhashable key or the end
of the file, after which nothing is read. The ratings are:

- A pickle that hands what `find_class` returned to anything but the stack and the
  memo before it ends is `unsafe-code-execution`, wherever it starts and whatever
  follows: `REDUCE`, `INST`, `OBJ`, `NEWOBJ` and `NEWOBJ_EX` call it, `BUILD` calls its
  `__setstate__`, `SETITEM`, `SETITEMS`, `APPEND`, `APPENDS` and `ADDITEMS` call its
  `__setitem__`, `extend`, `append` or `add` (so `builtins.__dict__['len'] = os.system`
  or `os.environ['LD_PRELOAD'] = ...` needs no call opcode), and a key, set item,
  argument list, state, buffer or `STACK_GLOBAL` string that is the resolved object
  runs its methods or passes a type check an object of the right type would pass. A
  call reached only through a module that no finder can name, or through a storage
  that a loader's `persistent_load` returned, counts for nothing. A `BINPERSID` of a
  `("module", obj, ...)` id gives back `obj`, as the `persistent_load` of `torch.load`'s
  legacy format returns it, so a call of what `obj` resolved counts.
- A pickle that the 64 KiB, opcode or MARK bound cuts short before the loader's
  behaviour is decided is `unknown` wherever it starts, in a file inventoried by its
  content too, and the explanation says whether it had already resolved an importable
  name. So a pickle padded with harmless opcodes, such as `N0` (NONE, POP) repeated, or
  with a string longer than 64 KiB, before what it calls is `unknown` and inventoried,
  unless a pickle-family name says a loader unpickles it, which rates it
  `unsafe-code-execution` with that explanation.
  Text ends or fails before a bound, as two reads past the sample are decided without
  the bytes they miss: one that ends past the end of the file, which the C unpickler
  fails as truncated and the pure-Python one follows to the end of the file, and a
  text argument whose visible part already fails, such as a STRING that opens with no
  quote (`SIMPLE  = T`), an `INT`, `LONG`, `FLOAT`, `GET` or `PUT` with a character or a
  space that no number takes (`Infinity and beyond`), a `GLOBAL` line that is not UTF-8,
  or an `INST` line or `PERSID` that is not ASCII. Any other module or name line is
  left undecided: the loaders import the module before they look the name up, and
  `importlib` imports a file named `ev-il.py` or `evil x.py`. A line that
  starts inside a frame is not decided early. Each offset where a loader resumes is
  read once.
- A pickle that resolves an importable name and never uses it is `unknown`, as the
  loader imported the name, when it returns it at STOP (`cos\nsystem\n.`) or, when the
  pickle starts with PROTO or the file has a model name, when it ends at an error. A pickle
  that ends before `find_class` returns, and a text-protocol one found by content that
  names something before an error, are not components: `VERSION`, `.h`, `cache`,
  `logs`, `README.md` reads as a pickle whose memo read fails before anything is
  resolved, and `VERSION`, `.cache`, `build`, `bin` as one whose BUILD has no
  operands.

A pickle whose STOP falls inside a protocol 4 or 5 FRAME with bytes left in the frame
is read on from both places a loader resumes: after the frame, as `io.BytesIO` and an
unbuffered file give the bytes, and right after the STOP, as the C unpickler reading a
buffered file, such as the one `torch.load` opens for a path, does. The worse reading
counts, and such a file is rated `unknown` at least. Under a model suffix, the pickle
family included, content is also recognized by its shape: a binary
pickle with PROTO and 16 well-formed opcodes in its first 64 KiB, or a stream that
passes `pickletools` checks to its first STOP, is `unsafe-code-execution`. A
pickle-family name rates no content but a pickle, a compressed or archived stream
and a file that starts with the GGUF magic: a pickle opcode stream that a
bound cuts short before a recognized shape or a call is `unsafe-code-execution`
under such a name, with the evidence `Potential code-executing loader format (...)`
around the bounded verdict, as the loader unpickles whatever it holds; a readable
file whose first 64 KiB start no pickle, NumPy array, ZIP archive, compressed or
archived stream or GGUF magic is `unknown`,
with the evidence `Named pickle-family format; no pickle evidence in the inspected
prefix` (`empty file` for a zero-length one); and a file that cannot be read keeps
the loader's `unsafe-code-execution` rating by name. Under a pickle-family name, a
ZIP archive whose directory is malformed or over 1 MiB, or with a member that was
not checked, and a NumPy array whose header is past the inspection limits are
`unsafe-code-execution` with the evidence `Potential code-executing loader format
(...)` around that verdict, as `torch.load` and `np.load` still read past the bound;
so is a compressed or archived stream, named with a wrapper suffix (`.tar`, `.gz`,
`.bz2`, `.xz`, `.lzma`, `.zst`, `.z`, `.lz4`, `.zip`) or starting with gzip, zlib, bzip2, xz, Zstandard,
LZ4 frame or joblib `ZF` magic, an LZMA-alone header after joblib's `5d 00`, the
ustar magic at offset 257, or a tar header that `tarfile` reads without that magic,
which pandas, joblib and `torch.load` unwrap before they unpickle, with the evidence
`Potential code-executing loader format (compressed or archived stream; decompressed
content not inspected)`. An LZMA-alone header is read from the first 14 bytes:
joblib's `5d 00`, which it detects whatever dictionary size follows, an uncompressed
size that is unknown or below 2^63, and a zero byte after it, where the range coder
starts. A tar header is a first 512-byte block whose checksum `tarfile` accepts and
whose mode, owner, size, time and device numbers it parses, whatever its name and
type. A raw array whose first bytes happen to form such a header is rated critical
by it: a little-endian integer array whose first value is 93, such as a `labels.bin`
of 32-bit integers 93 to 156, opens with an LZMA-alone header, and, rarely, a float32
array, such as one upcast from bfloat16, opens with a tar header that `tarfile`
reads. A file that starts with the GGUF magic, whatever follows,
as with the wrapper magics, is `unsafe-code-execution` too under a pickle-family
name, with the evidence `Potential code-executing loader format
(GGUF content under a pickle-family name; its chat templates are not inspected under
this name)`: llama.cpp opens a model by its magic, not its name, and the chat-template
check below runs only under a `.gguf` name. Only a ZIP archive whose directory was
read whole and lists no pickle-family member or object-dtype array keeps its
`unknown` verdict.
Any other content, such as a numeric NumPy array or a ZIP archive with
neither a pickle-family member nor an object-dtype array as a member, is not a
component. Each such file is opened once, after every file that the models with a
name bind and their directories configure has been read, and only if it is not one
of those files. Reading stops as soon as its content is known not to be a payload:
after the first 8 bytes when they can start no pickle, NumPy array or ZIP archive,
after at most 64 KiB when they can start a pickle, and after the header of a NumPy
array; a ZIP archive is read to its end, as a model archive is. A component is
digested from the same read, so each byte is charged once to the `model-total-bytes`
limit. A file larger than the `model-bytes` limit is a collection failure, as a
model file is.

Each model file is one component. Its `bom_ref` is `model:` followed by the
file's path relative to the scanned root, and its `name` and `source_path` are
that relative path, so the same tree scanned at two locations produces identical
records, and two files with the same name in directories with the same name stay
distinct.

The serialization rating is:

| Rating | When |
| --- | --- |
| `unsafe-code-execution` | A pickle-family name whose file cannot be read, whose first 64 KiB hold a pickle opcode stream, recognized or cut short by a bound, or a compressed or archived stream, or starts with the GGUF magic (whose chat templates are inspected only under a `.gguf` name), or whose ZIP archive or NumPy array a bound left unread; or, under any model suffix and for a file inventoried by its content, content recognized as a binary or text-protocol pickle, a NumPy array with an object dtype, which `np.load(allow_pickle=True)` unpickles, or a ZIP archive with a pickle-family member (`.pkl`, as `torch.save` writes `data.pkl`, `.pickle`, the other listed suffixes, or such a name inside one or two wrapper suffixes such as `.pkl.gz` or `.pkl.tar.gz`) or with such an array as a member. A pickle is recognized when `pickle.load`, read as [above](#model-files-and-references), calls or changes what it resolved within the first 64 KiB and 4,096 opcodes, before any flaw that ends it, as `pickle.load` runs that call first. Under a model suffix, a binary pickle is also recognized by its PROTO opcode and at least 16 well-formed opcodes in its first 64 KiB, whatever follows them, and a text-protocol one by a consistent opcode stream of at most 4,096 opcodes to its first STOP. An object dtype is found in a NumPy version 1, 2 or 3 header of at most 64 KiB, which holds every version 1 header however it is padded, parsed as `np.load` parses it; only its `descr` value names types, in structured, nested and subarray dtypes too, so a field name is never taken for a type. A ZIP member's name is read from the archive's first local header or from its central directory, read from the end of the archive up to 1 MiB, including ZIP64, wherever a reader locates it: at the offset the end record stores, ending where the end record (or a ZIP64 record before a ZIP64 locator, whatever the classic record holds) starts, as `zipfile` and so `np.load` locate it, and at the ZIP64 locator's offset; a member that any of these directories lists is rated, so a decoy directory hides none, and an archive where any of them lies beyond that bound, or starts but cannot be read, is unread. As in `zipfile`, the end record is the last 22 bytes when they hold one without a comment, and a name, extra field or comment that runs past its directory is cut where the directory ends. A file that starts with an end record (`PK\x05\x06`), which `np.load` hands to `zipfile`, is read as an archive too. Every listed member, whatever its name, is checked for an array from its local header and the start of its data, stored or DEFLATE-compressed |
| `safe` | A SafeTensors file whose header is UTF-8 JSON with string metadata, known dtypes and tensor spans that index the whole data region, with no configured chat template matching the access-pattern heuristic. The rating is not a guarantee that the template is safe; `validate` compares templates only through its completeness check |
| `unsafe-template-injection` | A GGUF file whose embedded chat template matches the access-pattern heuristic, or a SafeTensors file that would be `safe` in a directory whose Hugging Face chat template matches it. A match does not establish that the renderer executes the pattern or that its sandbox is bypassed |
| `unknown` | Everything else, including ONNX, GGUF, Keras, HDF5, SavedModel, TFLite, Core ML and ExecuTorch files, a readable pickle-family file whose first 64 KiB start no recognized pickle, NumPy array, ZIP archive, compressed or archived stream or GGUF magic (`Named pickle-family format; no pickle evidence in the inspected prefix`, or `empty file` for a zero-length one), a pickle under any other name that the 64 KiB, 4,096-opcode or 64-MARK bound cuts short before `pickle.load` calls anything, where [the check above](#model-files-and-references) rates it, a SafeTensors header over the 1 MiB inspection limit, a NumPy array header over 64 KiB or past the 16,000,000 structure units one scan shares with the ONNX and GGUF readers, at one unit a header byte, and a ZIP archive whose central directory is malformed or over 1 MiB or that has a member that was not checked: one compressed by another method, such as BZIP2 or LZMA, one whose data runs past the next member's local header, or one with an array header past those limits; under a pickle-family name, such a NumPy array or ZIP archive is `unsafe-code-execution` instead |

### Format and model type

The rating says how a file loads, not what it is. A component's `serialization_format`
is the format its file name claims or, for a file inventoried by its content, what
that content was recognized as. Its `model_type` is inferred from the directory's
configuration and the file name, and is `foundation` when neither says otherwise.
Neither field shows that the file was read as that format, except for the two formats
whose header the collector checks: a `.gguf` or `.safetensors` file is recorded with
its format (`llama.cpp` or `safe-tensors`) and a model type only when its header is
that format's, which is the four bytes `GGUF` at the start of a `.gguf` file whose
content is not rated `unsafe-code-execution` (those bytes also open a pickle), and a
`.safetensors` header that validates, as the `safe` rating requires. Any other file
under those two suffixes is still a component, with the rating and the findings its
content gets, but its record has neither field. Instead `properties.named_format`
holds the format its name claims, and `properties.format_inspection`, which every
model file has, says what the check found:

| `format_inspection` | When |
| --- | --- |
| `Named as GGUF, but the content does not start with the GGUF magic; the format was not established` | A `.gguf` file of at least four bytes that does not start with `GGUF` |
| `Named as GGUF, but too short to hold the GGUF magic; the format was not established` | A `.gguf` file shorter than four bytes |
| `Malformed or unsupported SafeTensors structure` | A `.safetensors` file whose header does not validate, or that is shorter than the eight bytes of its header length |
| `SafeTensors header exceeds the inspection limit` | A `.safetensors` file whose header is longer than 1 MiB |
| `Artifact could not be inspected` | A file that could not be read, which is also a collection failure |

A `.gguf` file whose content the checks above rate as a pickle, a NumPy array or a ZIP
archive, and a `.safetensors` file whose content they rate `unsafe-code-execution`,
keep the explanation of that content instead.

A text file named `not_a_model.gguf` is therefore a component rated `unknown`, with
the high `serialization_format_unknown` finding and no format or model type, not a
`foundation` model in `llama.cpp` format. A file named as SafeTensors that is rated
`unknown` also gets the high `invalid_safetensors` finding from `risk`, which fails
the gate at any score. A `.gguf` file that starts with the magic keeps its format and
model type when its version or metadata cannot be read, and `properties.gguf_metadata`
says so. No other suffix has a header check, so a file under one of them is recorded
with the format its name claims and a model type, whatever it holds.

## Files bound to the weights

Some formats keep weights outside the file the collector rates. The collector
binds those files to the model by SHA-256 and lists them, with paths relative to
the root, in the component's `properties.weight_files`:

| Layout | Bound files |
| --- | --- |
| ONNX with external data | Every file that a tensor stored as `EXTERNAL` names in its `location`, in graph initializers, node attributes, subgraphs, functions and training graphs |
| TensorFlow SavedModel | Every file under `variables/`, `assets/` and `assets.extra/`, and `fingerprint.pb` and `keras_metadata.pb`, beside `saved_model.pb` |
| Sharded checkpoints | The shard index (for example `model.safetensors.index.json` or `pytorch_model.bin.index.json`) on every shard it lists |

An external-data location that leaves the model's directory or names a missing
file, a shard index that lists a missing file, a file in another directory or a
file that is not a collected model file, and an ONNX file that may name external
data the reader cannot attribute are collection failures. The reader counts a
`location` key in every encoding a protobuf runtime accepts, including the
over-long tags whose low 32 bits protobuf's C++ parser keeps; in a file it can
parse, each such key must be an external-data entry it read or a name, and a
file it cannot parse, or one beyond its limits, fails whenever the bytes
`location` occur in it at all. A tensor's `data_location` is read as protobuf
reads the enum: as a 32-bit value, where a later value that the enum does not
define never replaces an earlier `EXTERNAL`. A singular tensor field written more
than once, such as a node attribute's tensor, which protobuf merges into one
tensor, is a file the reader cannot parse.

When `variables/`, `assets/` or `assets.extra/` beside a SavedModel graph is a
symlink to a directory in the project, the files below it are bound under the
names a loader opens through the link, and they are hashed without following it,
so each is a collection failure. When one of those directories, `fingerprint.pb`
or `keras_metadata.pb` is absent, another spelling of its name that differs only
by case or Unicode normalization is a failure, because case-insensitive file
systems open it.

A file that many models bind costs one binding per model, so the bindings are
bounded. A directory with more than 16 shard indexes binds none of them and
fails. One scan records at most twice the `entries`
[collection limit](collection-limits.md) in bindings (200,000 by default),
counting each distinct entry of a shard index once when the index is read and
each file once for every model it is bound to; beyond that, the scan fails and
binds nothing more to the remaining models. A model whose bindings were refused, or
whose directory holds a shard index that was refused, is never reported verified on
its own file alone: where its signer policy entries would
verify it, its `signing_status` is `partially-verified`, its trust tier `unknown`, and
its signing claim names the exhausted budget as the reason. The same holds for a
shard whose directory holds a shard index that could not be read or parsed, or whose
`weight_map` is not a map of names to files or names no collected weight file, and for
every model in a directory with more than 16 shard indexes: the claim names the shard
index that could not be bound. The check is conservative: any such index in the
directory downgrades every pinned model file there, including one that a loader would
reach through a different, well-formed index, such as a SafeTensors shard beside a
broken `pytorch_model.bin.index.json`.

A bound file that is a content candidate, such as ONNX external data named
`checkpoint` under `models/` or a file below a SavedModel's `variables/`, is rated by
its content from the read that digests it, as a file no model binds is: when that
content is a payload, or was left unread at a bound, the file is also a component of
its own, with its own rating and finding, beside its digest in the model's
`weight_files`.

`validate --project` observes the files again and fails with
`weight_files_mismatch` when they differ from the BOM's record, so replacing one
shard or one external-data file fails integrity and changes the inventory. For
this model check, one validation walks each model directory once, reads a file
that many models share once rather than once per model, verifies each policy
entry once, and reads and binds at most what one scan may (the
`model-total-bytes` limit, and twice the `entries` limit in bindings). A model
beyond either budget gets the `unknown` issue `validation_budget_exhausted`. In
addition, `validate` charges the model's own file, each Sigstore verification of
it and the file-hash check's digests (each algorithm computed once per run) to
the validation's artifact budget, six times the `model-total-bytes` limit
(1.5 TiB by default), and
a second model component that names the same weights file, or the same artifact
the signer policy names, fails as `duplicate_artifact`.

## Configuration, tokenizer, chat templates and custom code

For every directory that holds a model, the collector reads and digests these
files when present, and records the digests on each model in the directory:

| Field | Source files |
| --- | --- |
| `properties.config_files` | `config.json`, `model_config.json`, `adapter_config.json`, `tokenizer_config.json`, `generation_config.json`, `quantize_config.json`, `preprocessor_config.json`, `processor_config.json`, `chat_template.json`; each must be a JSON object |
| `tokenizer_hash`, `properties.tokenizer_files` | `tokenizer.json`, `tokenizer.model`, `spiece.model`, `sentencepiece.bpe.model`, `vocab.json`, `vocab.txt`, `merges.txt`, `special_tokens_map.json`, `added_tokens.json` |
| `chat_template_hash`, `properties.chat_templates` | `chat_template` in any of the configuration files, as a string or a list of named templates; `chat_template.jinja`, `chat_template.jinja2` and `additional_chat_templates/*.jinja`; the `tokenizer.chat_template` entries embedded in a GGUF file, with each key read up to its first NUL byte, as llama.cpp reads it |

`tokenizer_hash` and `chat_template_hash` are manifest digests: the SHA-256 of
the RFC 8785 JSON `{"files": [{"path": ..., "sha256": ...}]}` built from the
recorded list, sorted by path (for a chat template, the path is the source,
such as `tokenizer_config.json#chat_template`).

An `additional_chat_templates` symlink to a directory in the project is read
through the link, under the names a loader opens. When one of these files or that
directory is absent, another spelling of its name that differs only by case or
Unicode normalization is a failure, because case-insensitive file systems open it.

Every model records these digests for its directory, so one scan records at
most twice the `entries` limit of them across its models (200,000 by default),
counting each configuration file,
tokenizer file, chat template, custom-code reference and Python file once per
model. Beyond that, the scan fails and the remaining models record none of
these lists, `tokenizer_hash` or `chat_template_hash`.

`trust_remote_code` is `true` when any configuration file says so, so an empty
`config.json` cannot hide it in a later file. A configuration that declares
`auto_map` or `custom_pipelines` declares custom code, which the loader imports
only with `trust_remote_code`: the model gets a high `custom_code` finding, and
`properties.custom_code` records which files declare it, the well-formed module
references, whether any reference names another repository, and the digests of
the directory's `.py` files and the referenced modules below it. A module named as
holding credentials, such as `secrets.py` or `token_utils.py`, is not read and is a
coverage gap instead, as a change to it would raise no drift alert. Without such a declaration, Python files are not
recorded, so adding an unrelated script does not change the inventory. The
`base_model_name_or_path` of an `adapter_config.json` is recorded as
`properties.base_model` when it is a Hugging Face model identifier.

In `diff`, a change to `tokenizer_hash` or `chat_template_hash` is a high alert,
and a change to a bound weight file, a configuration file or custom code is a
high alert naming the property that records its digest.

Every chat template that `properties.chat_templates` lists is checked for potential
Python-internals access patterns: a dunder attribute, named or subscripted, a
dunder name as a string such as an `attribute=` argument, the `attr` filter, a
Python-mangled private name such as `self._TemplateReference__context`, read as an
attribute or written as a string, or an underscore string repeated with `*`.
The heuristic decodes string escapes such as `\x5f`, removes a backslash before a
line break, and folds adjacent constant strings joined with `~` or `+`, or written
next to each other, inside Jinja expressions. It does not evaluate templates.
Matches may be harmless in the actual context; a correctly configured sandbox can
deny the access. Other ways to construct names may not match. A Hugging Face template
that matches gives every
model in its directory a critical `serialization_format` finding that names up to
three matching templates and counts the rest, and a model that would otherwise be
rated `safe` is rated `unsafe-template-injection`. A model rated `unknown` or
`unsafe-code-execution` keeps its rating and the findings that come with it, such as
`invalid_safetensors` for a SafeTensors file that does not validate, so a suppression
of the template finding does not accept them. `validate` checks each model file's own
structure again, not its directory's templates: its completeness check, on by
default, and `risk --project` compare the rating and the finding with a new
collection. A template file larger than the `file-bytes` limit is digested but not
checked, and is a coverage gap in `surfaces_excluded`.

A GGUF file whose metadata exceeds the reader's bounds (65,536 keys, 16 MiB
strings, 2,097,152 array items, arrays nested more than two deep, 128 MiB of
metadata, or the 16,000,000
structure units one scan may spend on ONNX and GGUF files and NumPy array headers)
keeps the rating `unknown`, records `properties.gguf_metadata` and is a coverage gap in
`surfaces_excluded`, because its chat templates were not inspected.

## Operator signature policy

A model passes integrity only when every one of its weight files (the model file
and the files bound to it) verifies under a signature policy you own. Pass the
same policy to `scan`, `validate --project`, `risk --project` and `baseline`
with `--signature-policy`, or to the GitHub Action with `signature-policy`.

Keep the policy outside the checkout: the commands refuse a policy file inside
the scanned project or anywhere in any enclosing Git working tree, including a
superproject above a nested checkout or submodule (so a
monorepo's `ci/signers.json` is refused when you scan `services/agent`), or in
any Git working tree that holds the directory the command runs from (so a
pull request's checkout cannot supply the policy for an artifact scanned elsewhere), also
under another name for any of these directories such as a case variant or a bind mount
(compared by device and inode), or one with other hard links, and they resolve the project path first, so a symlinked `--project`
path works for every command. Every directory at or above the project with a `.git`
entry counts as an enclosing repository, so two layouts cannot hold the policy: a
trusted base checkout that encloses the pull request's checkout (the base at the
workspace root, the pull request in `pr/`), and a home directory that is itself a
repository (`~/.git`) when the project is below it. Every entry must name a file beneath the project,
spelled as its directory spells it: another case is refused on every file system,
also where file names fold case.
An entry that names neither a collected model weight file nor the ShadowScan
report makes the `model` collector fail, and `validate --project` reports it as
the integrity error `unused_policy_entry` even when the completeness check does
not run, so an entry can never look enforced while nothing checks it. An entry
beneath the directory of a model that got `validation_budget_exhausted` is not
reported as unused: that model's weight files were not all bound, and its
`unknown` issue already keeps integrity from passing.

The ShadowScan report is checked by the discovery producer check of
`validate --project` and `risk --project`, not by `scan`, and only through a
`sigstore-message-signature` entry for the report the collector reads, the first
of `.shadowscan/report.json`, `shadowscan-report.json` and `shadowscan.json`
that exists. Its `expected_sha256`, if set, must equal the report's digest. A
`digest-pin` entry for the report, or an entry for another report location, is
an unused entry.

Version 1 policies stay valid; every entry is a Sigstore message signature:

```json
{"version": 1, "artifacts": [{"artifact_path": "models/classifier.safetensors",
  "bundle_path": "models/classifier.safetensors.sigstore.json",
  "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com"}]}
```

Version 2 names a `kind` on every entry and rejects unknown kinds and fields:

```json
{"version": 2, "artifacts": [
  {"kind": "sigstore-message-signature", "artifact_path": "models/classifier.safetensors",
   "bundle_path": "models/classifier.safetensors.sigstore.json",
   "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/heads/main",
   "expected_issuer": "https://token.actions.githubusercontent.com",
   "expected_sha256": "sha256:<hex>"},
  {"kind": "digest-pin", "artifact_path": "models/onnx/model.onnx_data",
   "expected_sha256": "sha256:<hex>"}]}
```

- `sigstore-message-signature` verifies a Sigstore bundle offline over the
  file's SHA-256, under the exact identity and OIDC issuer. Produce the bundle
  with sigstore-python, for example `python -m sigstore sign --bundle
  model.safetensors.sigstore.json model.safetensors` in a workflow with an OIDC
  identity. A signature proves only that the identity signed those bytes at some
  time: anyone who can write to the checkout can put an older or another
  artifact signed by the same identity, with its bundle, in its place. The
  optional `expected_sha256` pins the exact bytes and closes that gap.
- `digest-pin` recomputes the file's SHA-256 through the collector's confined
  reader and compares it with `expected_sha256`. You are the trust root, as you
  are for the policy itself; no Sigstore install is needed. Compute the value
  with `sha256sum`. Note that `models/onnx/model.onnx_data` above illustrates
  `digest-pin` syntax on an auxiliary shard: `validate`'s model integrity gate
  still requires model weights to use SafeTensors format (`*.safetensors`) and
  pass structural validation alongside a matching signature or digest pin.

OpenSSF Model Signing signatures (`model.sig`) are not verified yet: they are
Sigstore bundles whose DSSE envelope signs an in-toto statement listing every
file's digest, not the file itself. Such a bundle named in a policy fails with
the reason `Bundle carries a DSSE envelope (an OpenSSF Model Signing signature
or an attestation); only Sigstore message-signature bundles are verified`. Pin
the files, or sign each weight file with a message signature, instead.

### Signing status and evidence

| `signing_status` | Meaning |
| --- | --- |
| `sigstore-signed` | Every weight file verified, the model file by its Sigstore signature |
| `digest-pinned` | Every weight file verified, the model file by its digest pin |
| `partially-verified` | Some weight files verified and no entry names the others |
| `verification-failed` | An entry did not verify: other bytes, another signer or issuer, a pin mismatch, or a bundle the verifier refused |
| `verification-unavailable` | A Sigstore entry could not be checked because the `sigstore` extra is not installed; the scan also fails with the install hint |
| `signature-present-unverified` | No entry, but a signature-looking file lies beside the model |
| `signature-not-found` | No entry and no signature-looking file |

The trust tier is `third-party-signed` for `sigstore-signed` and
`internal-verified` for `digest-pinned`. Whenever an entry was checked, the
component's `claims.signing_status` records how: `method`
(`sigstore-message-signature` or `digest-pin`), `assurance` (`verified` or,
after a failure, `observed` with the reasons in `unknown_reason`), the model
file as `locator`, and `evidence_refs` such as `policy:sha256:<policy file
digest>`, `digest-pin:<path>@sha256:<digest>`,
`sigstore-message-signature:<path>@sha256:<digest>`,
`bundle:<bundle path>@sha256:<bundle digest>`, `identity:<signer>` and
`issuer:<issuer>`. `validate` does not trust these records: it verifies every
weight file again from the policy. The `policy:` reference identifies the
policy file of the run, not the model, so project reconciliation and `diff`
ignore it: an equivalent policy with other bytes, or one with more entries, does
not make a verified model look mismatched or changed.

## What this does not establish

A pin or a signature shows that the bytes are the ones the operator or signer
approved, not that the model is benign. Formats rated `unknown` have no
structural validator: Keras Lambda layers, SavedModel operations and custom
TensorRT or TFLite operators are not inspected. A file under a name other than
those listed above is inventoried only by its content, and only under the names and
directories [listed above](#model-files-and-references): a pickle renamed outside
them, such as `assets/blob`, is not inventoried, nor is a pickle that the bounded
check does not recognize, such as a binary pickle whose first 64 KiB hold neither 16
opcodes nor its end, or a pickle inventoried by its content that calls nothing before
`pickle.load` would stop. SafeTensors
tensor bytes are hashed but not inspected, so a payload that also parses as
another format is not flagged. The chat template check is a heuristic, not template
analysis: a name assembled through variables, formatting, filters, nested expressions
or other operations can pass it, as can a template that instructs the model. The
heuristic does not establish whether a renderer is vulnerable or a sandbox escape
exists. Review templates and use an appropriately sandboxed renderer.
