{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.cidrwall;
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "cidrwall.toml" cfg.settings;
  usesBpf = (cfg.settings.xdp.rules or [ ]) != [ ] || (cfg.settings.tc.rules or [ ]) != [ ];
in
{
  options.services.cidrwall = {
    enable = lib.mkEnableOption "cidrwall CIDR blocklist enforcement";

    package = lib.mkPackageOption pkgs "cidrwall" { };

    settings = lib.mkOption {
      inherit (settingsFormat) type;
      default = { };
      description = ''
        Contents of `cidrwall.toml`; see `share/cidrwall/cidrwall.toml` in the package for every key.
        The service runs `cidrwall --check` before every start.
      '';
      example = lib.literalExpression ''
        {
          files = { inbound = "/var/lib/blockmerge/output/inbound.txt"; outbound = "/var/lib/blockmerge/output/outbound.txt"; };
          zones = { WAN = [ "wan0" ]; LOCAL = { interfaces = [ ]; local = true; }; };
          xdp.rules = [ { blocklist = "inbound"; ingress_zones = [ "WAN" ]; } ];
          tc.rules = [ { blocklist = "outbound"; egress_zones = [ "WAN" ]; } ];
        }
      '';
    };

    after = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "blockmerge.service" ];
      description = "Units that produce the blocklist files and must start first.";
    };

    readPaths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      description = "Directories containing the blocklist files, made readable inside the sandbox.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.cidrwall = {
      description = "Atomically apply CIDR blocklists";
      wantedBy = [ "multi-user.target" ];
      wants = cfg.after;
      after = [ "network.target" ] ++ cfg.after;
      restartTriggers = [ configFile ];

      serviceConfig = {
        ExecStartPre = "${lib.getExe cfg.package} --config ${configFile} --check";
        ExecStart = "${lib.getExe cfg.package} --config ${configFile}";
        Restart = "always";
        RestartSec = "5s";
        # Root (with a minimal capability bounding set) because pins live under the
        # root-owned, mode 0700 bpffs mount.
        User = "root";

        AmbientCapabilities = [
          "CAP_NET_ADMIN"
        ]
        ++ lib.optionals usesBpf [
          "CAP_BPF"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
        ]
        ++ lib.optionals usesBpf [
          "CAP_BPF"
          "CAP_PERFMON"
          "CAP_SYS_ADMIN"
        ];
        # Pinned links and maps live on the host bpffs and must survive restarts.
        ReadWritePaths = lib.optional usesBpf "/sys/fs/bpf";
        ReadOnlyPaths = cfg.readPaths;
        LimitMEMLOCK = "infinity";

        LockPersonality = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_NETLINK"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
