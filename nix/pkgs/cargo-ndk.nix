{
  rustPlatform,
  fetchCrate,
}:

rustPlatform.buildRustPackage {
  pname = "cargo-ndk";
  version = "3.5.4";

  src = fetchCrate {
    pname = "cargo-ndk";
    version = "3.5.4";
    hash = "sha256-QuuR4h17tiw32B1FOeQ2zCvhw0kbnza/B4Xr7lfcL8s=";
  };

  cargoHash = "sha256-/d0UlBFp2TmMax4bchmpVkQbixQm5QeNnpp/9X5f+9Y=";

  meta.mainProgram = "cargo-ndk";
}
