{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [
    pkgs.git
    pkgs.dotenvy
  ];

  # https://devenv.sh/languages/
  languages.rust.enable = true;
  languages.python = {
    enable = true;
    uv.enable = true;
  };

  enterTest = ''
      cd dataset
      dotenvy cargo test -- --nocapture
    '';
}
