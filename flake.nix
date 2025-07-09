{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default =
          with pkgs;
          mkShell {
            packages = [
              (python313.withPackages (
                ps: with ps; [
                  uv
                ]
              ))
            ];
            shellHook = ''
              # https://nixos.wiki/wiki/Python#uv

              # We will manage Python interpreters via Nix.
              export UV_PYTHON_DOWNLOADS="never"
              # Ensure uv respects the devShell's Python.
              export UV_PYTHON="$(which python)"

              # Activate the virtual environment
              source ./.venv/bin/activate
            '';
          };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
