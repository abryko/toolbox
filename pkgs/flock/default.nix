{ lib
, sources
, stdenv
, fetchzip
, autoreconfHook
, ronn
}:

stdenv.mkDerivation rec {
  source = sources.flock;
  pname = "flock";
  version = source.version;

  src = fetchzip {
    inherit (source) url sha256;
  };
  patches = [./fix-int-type-verbose.patch];

  nativeBuildInputs = [ autoreconfHook ];
  buildInputs = [ ronn ];

  meta = with lib; {
    description = "Cross-platform version of flock(1)";
    homepage = "https://github.com/discoteq/flock";
    license = licenses.mpl20;
    maintainers = with maintainers; [ eonpatapon ];
  };
}
