{
  rustPlatform,
  fetchCrate,
}:

rustPlatform.buildRustPackage {
  pname = "cargo-ndk";
  version = "4.1.0";

  src = fetchCrate {
    pname = "cargo-ndk";
    version = "4.1.0";
    hash = "sha256-4R2JhL0XUF+MQfau06y+z8Vu3B6rqeW//5zOyNTGvis=";
  };

  cargoHash = "sha256-Irsp8/ImI+0wLfdsCcqUT8kB6aZ49rm3wPtblK8jMks=";

  meta.mainProgram = "cargo-ndk";
}
