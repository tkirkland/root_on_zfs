#!/bin/bash
#
# Script installs Ubuntu on ZFS filesystem with snapshot rollback at boot.
# Options include encryption and headless remote unlocking.
#
# Source: https://github.com/Sithuk/ubuntu-server-zfsbootmenu
# Date: 2025-11-22
#
# Usage: script_filename {initial|postreboot|remoteaccess|datapool}
#
# Part 1: Run with the "initial" option from Ubuntu live ISO (desktop version).
# Part 2: Reboot into a new installation, login as user/password defined below.
# Part 3: Run with the "postreboot" option to complete installation.

# Log all output to a file
function log_func() {
  exec > >(tee -a "${log_loc}/${install_log}") 2>&1
}

# Display disclaimer and wait for confirmation
function disclaimer() {
  local _
  echo "***WARNING*** This script could wipe out all your data!"
  echo "Press Enter to Continue or CTRL+C to abort."
  read -r _
}

# Locate squashfs filesystem from live environment
function locate_squashfs() {
  local search_paths=(
    "/cdrom/casper/filesystem.squashfs"
    "/media/cdrom/casper/filesystem.squashfs"
    "/run/live/medium/casper/filesystem.squashfs"
    "/lib/live/mount/medium/casper/filesystem.squashfs"
    "/rofs"
  )
  local dev

  squashfs_path=""
  squashfs_type=""
  local mount_point

  # Check for already-mounted root filesystem (rofs)
  if [[ -d "/rofs" ]] && [[ -f "/rofs/etc/os-release" ]]; then
    squashfs_path="/rofs"
    squashfs_type="mounted"
    echo "Found mounted live filesystem at ${squashfs_path}"
    return 0
  fi

  # Search for the squashfs file
  for path in "${search_paths[@]}"; do
    if [[ -f "${path}" ]]; then
      squashfs_path="${path}"
      squashfs_type="squashfs"
      echo "Found squashfs at ${squashfs_path}"
      return 0
    fi
  done

  # Search mounted filesystems for the casper directory
  while IFS= read -r mount_point; do
    if [[ -f "${mount_point}/casper/filesystem.squashfs" ]]; then
      squashfs_path="${mount_point}/casper/filesystem.squashfs"
      squashfs_type="squashfs"
      echo "Found squashfs at ${squashfs_path}"
      return 0
    fi
  done < <(mount | grep -E "iso9660|udf|vfat" | awk '{print $3}')

  # Search /dev/disk for unmounted ISO
  echo "Squashfs not found in standard locations. Searching for ISO media..."
  for dev in /dev/sr* /dev/loop*; do
    [[ -b "${dev}" ]] || continue
    local tmp_mount="/tmp/iso_search_$$"
    mkdir -p "${tmp_mount}"
    if mount -o ro "${dev}" "${tmp_mount}" 2>/dev/null; then
      if [[ -f "${tmp_mount}/casper/filesystem.squashfs" ]]; then
        squashfs_path="${tmp_mount}/casper/filesystem.squashfs"
        squashfs_type="squashfs"
        echo "Found squashfs at ${squashfs_path} (mounted from ${dev})"
        return 0
      fi
      umount "${tmp_mount}" 2>/dev/null
    fi
    rmdir "${tmp_mount}" 2>/dev/null
  done

  echo "ERROR: Could not locate live filesystem squashfs."
  echo "Searched locations:"
  for path in "${search_paths[@]}"; do
    echo "  - ${path}"
  done
  echo "Also searched mounted ISO media and loop devices."
  exit 1
}

# Check for live desktop environment
function live_desktop_check() {
  if ! dpkg -l kubuntu-desktop &>/dev/null; then
    echo "Desktop environment test failed. Run from live desktop."
    exit 1
  fi

  if ! grep -q casper /proc/cmdline; then
    echo "Live environment test failed. Run from live desktop."
    exit 1
  fi

  echo "Desktop environment test passed."
  echo "Live environment present."

  local live_version
  local live_version
  # shellcheck source=/dev/null
  live_version="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  live_version="${live_version,,}"  # lowercase

  if [[ "${live_version}" != "${ubuntu_ver,,}" ]]; then
    echo "Live environment version mismatch."
    echo "Live version must match Ubuntu version to install."
    exit 1
  fi

  echo "Live environment version test passed."
}

# Identify apt data sources location
function identify_apt_data_sources() {
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    apt_data_sources_loc="/etc/apt/sources.list.d/ubuntu.sources"
  else
    apt_data_sources_loc="/etc/apt/sources.list"
  fi
}

# Configure keyboard and console settings
# bashsupport disable=BP2001
function keyboard_console_settings() {
  kb_console_settings="/tmp/kb_console_selections.conf"

  apt-get install -y debconf-utils

  export debian_priority=high
  export debian_frontend=dialog
  dpkg-reconfigure keyboard-configuration
  dpkg-reconfigure console-setup
  export debian_priority="${install_warning_level#*=}"

  debconf-get-selections | grep keyboard-configuration > "${kb_console_settings}"
  debconf-get-selections | grep console-setup >> "${kb_console_settings}"
}
# Check minimum disk count for topology
function topology_min_disk_check() {
  local pool="$1"
  local topology_var="TOPOLOGY_${pool^^}"
  local disks_var="DISKS_${pool^^}"
  local topology="${!topology_var}"
  local disks="${!disks_var}"

  echo "Checking script variables for ${pool} pool..."
  echo "Topology: ${topology}, Disks: ${disks}"

  # Store for later use
  echo "${topology}" > "/tmp/topology_pool_pointer.txt"
  echo "${disks}" > "/tmp/disks_pointer.txt"

  local min_disks=0
  case "${topology}" in
    single)
      return 0
      ;;
    mirror|raid0|raidz1)
      min_disks=2
      ;;
    raidz2)
      min_disks=3
      ;;
    raidz3)
      min_disks=4
      ;;
    *)
      echo "Pool topology not recognised."
      exit 1
      ;;
  esac

  if [[ "${disks}" -lt "${min_disks}" ]]; then
    echo "A ${topology} topology requires at least ${min_disks} disks."
    exit 1
  fi

  echo "Minimum disk topology check passed for ${pool} pool."
}

# Get disk ID from user selection
function get_disk_id() {
  local pool="$1"
  local disk_num="$2"
  local total_disks="$3"
  local diskid_menu="/tmp/diskidmenu.txt"

  find /dev/disk/by-id -maxdepth 1 -type l ! -name '*-part*' \
    -exec sh -c 'for f; do printf "%s %s\n" "$(basename "$f")" "$(readlink "$f")"; done' _ {} + \
    | grep -vE "(CD-ROM|^nvme-eui\.|^nvme-nvme\.|_1 )" > "${diskid_menu}"

  echo "Please select Disk ID for disk ${disk_num} of ${total_disks} on ${pool} pool."
  nl "${diskid_menu}"

  local count
  count="$(wc -l < "${diskid_menu}")"
  local n=""

  while true; do
    read -r -p 'Select option: ' n
    if [[ "${n}" =~ ^[0-9]+$ ]] && [[ "${n}" -gt 0 ]] && [[ "${n}" -le "${count}" ]]; then
      break
    fi
  done

  diskid="$(sed -n "${n}p" "${diskid_menu}" | awk '{ print $1 }')"
  echo "Selected: '${diskid}'"

  # Validate selection
  if [[ ! -e "/dev/disk/by-id/${diskid}" ]]; then
    echo "Disk ID not found. Exiting."
    exit 1
  fi

  if grep -q "${diskid}" "/tmp/diskid_check_${pool}.txt" 2>/dev/null; then
    echo "Disk ID already selected. Exiting."
    exit 1
  fi

  echo "${diskid}" >> "/tmp/diskid_check_${pool}.txt"
}

# Get all disk IDs for a pool
function get_disk_id_pool() {
  local pool="$1"

  topology_min_disk_check "${pool}"

  echo "Carefully enter the ID of the disk(s) to destroy."

  # Create the temp file for duplicate checking
  : > "/tmp/diskid_check_${pool}.txt"

  local topology
  topology="$(cat /tmp/topology_pool_pointer.txt)"
  local disks
  disks="$(cat /tmp/disks_pointer.txt)"

  case "${topology}" in
    single)
      echo "The ${pool} pool topology is a single disk."
      get_disk_id "${pool}" "1" "1"
      ;;
    mirror|raid0|raidz*)
      echo "The ${pool} pool topology is ${topology} with ${disks} disks."
      for ((i = 1; i <= disks; i++)); do
        get_disk_id "${pool}" "${i}" "${disks}"
      done
      ;;
    *)
      echo "Pool topology not recognised."
      exit 1
      ;;
  esac
}

# Clear partition table on disks
function clear_partition_table() {
  local pool="$1"

  while IFS= read -r diskid; do
    echo "Clearing partition table on disk ${diskid}."
    sgdisk --zap-all "/dev/disk/by-id/${diskid}"
  done < "/tmp/diskid_check_${pool}.txt"
}

# Identify Ubuntu dataset UUID
function identify_ubuntu_dataset_uuid() {
  rootzfs_full_name="$(zfs list -o name | awk '/ROOT\/ubuntu/{print $1;exit}'\
    | sed -e 's,^.*/,,')"
}

# Find fastest apt mirror
function apt_mirror_source() {
  identify_apt_data_sources

echo "Choosing fastest up-to-date ubuntu mirror..."
  apt-get update
  apt-get install -y curl

  local ubuntu_mirror
  local codename
  codename="$(lsb_release -c | cut -f2)"
  local arch
  arch="$(dpkg --print-architecture)"
  local check_path="dists/${codename}-security/Contents-${arch}.gz"

  # Get 20 random mirrors to test
  local mirrors
  mirrors=$(curl -s "https://mirrors.ubuntu.com/${mirror_archive}.txt" | shuf -n 20)

  # Check each mirror for freshness
  ubuntu_mirror=$(
    for mirror in ${mirrors}; do
      local last_modified
      # Fetch headers with 5 s timeouts
      last_modified=$(curl -m 5 -sI "${mirror}${check_path}" | \
        sed 's/\r$//' | grep "Last-Modified" | awk -F": " '{ print $2 }')

      if [[ -n "${last_modified}" ]]; then
        local ts
        ts=$(LANG=C date -d "${last_modified}" -u +%s 2>/dev/null)
        if [[ -n "${ts}" ]]; then
          echo "${ts} ${mirror}"
        fi
      fi
    done | sort -rg | awk '{ if (NR==1) TS=$1; if ($1 == TS) print $2 }'
  ) || true

  # shellcheck disable=SC2016  # Single quotes intentional
  ubuntu_mirror=$(echo "${ubuntu_mirror}" | xargs -I {} sh -c \
    'echo "$(curl -r 0-102400 -m 5 -s -w %{speed_download} -o /dev/null {}ls-lR.gz)" {}' \
    | sort -g -r | head -1 | awk '{ print $2 }') || true

  if [[ -z "${ubuntu_mirror}" ]]; then
    echo "No mirror identified. No changes made."
  elif [[ "${ubuntu_original}" != "${ubuntu_mirror}" ]]; then
    cp "${apt_data_sources_loc}" "${apt_data_sources_loc}.non-mirror"
    sed -i "s,${ubuntu_original},${ubuntu_mirror},g" "${apt_data_sources_loc}"
    echo "Selected '${ubuntu_mirror}'."
  else
    echo "Identified mirror is already selected."
  fi
}

# Copy install log to a new installation
function log_copy() {
  if [[ -d "${mountpoint}" ]]; then
    cp "${log_loc}/${install_log}" "${mountpoint}${log_loc}/"
    echo "Log file copied into new installation."
  else
    echo "No mountpoint dir present. Install log not copied."
  fi
}

# Copy script to a new installation
function script_copy() {
  cp "$(readlink -f "$0")" "${mountpoint}/home/${new_user}/"
  local script_loc
  script_loc="/home/${new_user}/$(basename "$0")"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		chown "${new_user}:${new_user}" "${script_loc}"
		chmod +x "${script_loc}"
	EOCHROOT

  if [[ -f "${mountpoint}${script_loc}" ]]; then
    echo "Install script copied to new installation."
  else
    echo "Error copying install script."
  fi
}



# Create ZFS pool
function create_zpool() {
  local pool="$1"
  local ashift zpool_password zpool_encrypt zpool_partition zpool_name topology keylocation

  case "${pool}" in
    root)
      ashift="${zfs_rpool_ashift}"
      keylocation="prompt"
      zpool_password="${zfs_root_password}"
      zpool_encrypt="${zfs_root_encrypt}"
      zpool_partition="-part3"
      zpool_name="${rpool}"
      topology="${topology_root}"
      ;;
    data)
      ashift="${zfs_dpool_ashift}"
      zpool_password="${zfs_data_password}"
      zpool_encrypt="${zfs_data_encrypt}"
      zpool_partition=""
      zpool_name="${datapool}"
      topology="${topology_data}"

      if [[ -n "${zfs_root_password}" ]]; then
        case "${zfs_root_encrypt}" in
          native)
            keylocation="file:///etc/zfs/${rpool}.key"
            ;;
          luks)
            keylocation="file:///etc/cryptsetup-keys.d/${rpool}.key"
            ;;
        esac
      else
        keylocation="prompt"
      fi
      ;;
  esac

  local zpool_create_temp="/tmp/${pool}_creation.sh"

  cat > "${zpool_create_temp}" <<EOF
zpool create -f \\
  -o ashift=${ashift} \\
  -o autotrim=on \\
  -O acltype=posixacl \\
  -O compression=${zfs_compression} \\
  -O normalization=formD \\
  -O relatime=on \\
  -O dnodesize=auto \\
  -O xattr=sa \\
EOF

  if [[ "${pool}" == "root" ]]; then
    echo "  -O canmount=off \\" >> "${zpool_create_temp}"
  fi

  if [[ -n "${zpool_password}" && "${zpool_encrypt}" == "native" ]]; then
    cat >> "${zpool_create_temp}" <<EOF
  -O encryption=aes-256-gcm \\
  -O keylocation=${keylocation} \\
  -O keyformat=passphrase \\
EOF
  fi

  if [[ "${pool}" == "root" ]]; then
    echo "  -O mountpoint=/ -R ${mountpoint} \\" >> "${zpool_create_temp}"
  else
    echo "  -O mountpoint=${datapool_mount} \\" >> "${zpool_create_temp}"
  fi

  # Add topology and disks
  case "${topology}" in
    single|raid0)
      echo "  ${zpool_name} \\" >> "${zpool_create_temp}"
      ;;
    mirror)
      echo "  ${zpool_name} mirror \\" >> "${zpool_create_temp}"
      ;;
    raidz1)
      echo "  ${zpool_name} raidz1 \\" >> "${zpool_create_temp}"
      ;;
    raidz2)
      echo "  ${zpool_name} raidz2 \\" >> "${zpool_create_temp}"
      ;;
    raidz3)
      echo "  ${zpool_name} raidz3 \\" >> "${zpool_create_temp}"
      ;;
  esac

  # Add disk devices
  local loop_counter=1
  while IFS= read -r diskid; do
    if [[ -n "${zpool_password}" && "${zpool_encrypt}" == "luks" ]]; then
      echo -e "${zpool_password}" | \
        cryptsetup -q luksFormat -c aes-xts-plain64 -s 512 -h sha256 \
        "/dev/disk/by-id/${diskid}${zpool_partition}"

      local luks_dmname="luks${loop_counter}"

      while [[ -e "/dev/mapper/${luks_dmname}" ]]; do
        ((loop_counter++))
        luks_dmname="luks${loop_counter}"
      done

      echo -e "${zpool_password}" | \
        cryptsetup luksOpen "/dev/disk/by-id/${diskid}${zpool_partition}" "${luks_dmname}"

      echo "${luks_dmname}" >> "/tmp/luks_dmname_${pool}.txt"
      echo "  /dev/mapper/${luks_dmname} \\" >> "${zpool_create_temp}"

      ((loop_counter++))
    else
      echo "  /dev/disk/by-id/${diskid}${zpool_partition} \\" >> "${zpool_create_temp}"
    fi
  done < "/tmp/diskid_check_${pool}.txt"

  # Remove trailing backslash from last line
  sed -i '$ s/ \\$//' "${zpool_create_temp}"

  # Create the pool
  echo "${zpool_password}" | sh "${zpool_create_temp}"
}

# Update crypttab for auto-unlock
function update_crypttab() {
  local script_env="$1"
  local pool="$2"

  cat > "/tmp/update_crypttab_${pool}.sh" <<EOSCRIPT
#!/bin/bash
set -euo pipefail

case "${pool}" in
  root)
    zpool_password="${zfs_root_password}"
    zpool_partition="-part3"
    crypttab_parameters="luks,discard,initramfs"
    ;;
  data)
    zpool_password="${zfs_data_password}"
    zpool_partition=""
    crypttab_parameters="luks,discard"
    ;;
esac

apt-get install -y cryptsetup

loop_counter=1
while IFS= read -r diskid; do
  luks_dmname="\$(sed "\${loop_counter}q;d" "/tmp/luks_dmname_${pool}.txt")"
  blkid_luks="\$(blkid -s UUID -o value "/dev/disk/by-id/\${diskid}\${zpool_partition}")"

  echo "\${zpool_password}" | \\
    cryptsetup -v luksAddKey "/dev/disk/by-uuid/\${blkid_luks}" "/etc/cryptsetup-keys.d/${rpool}.key"

  echo "\${luks_dmname} UUID=\${blkid_luks} /etc/cryptsetup-keys.d/${rpool}.key \${crypttab_parameters}" >> /etc/crypttab

  ((loop_counter++))
done < "/tmp/diskid_check_${pool}.txt"

sed -i 's,#KEYFILE_PATTERN=,KEYFILE_PATTERN="/etc/cryptsetup-keys.d/*.key",' \\
  /etc/cryptsetup-initramfs/conf-hook
EOSCRIPT

  case "${script_env}" in
    chroot)
      cp "/tmp/diskid_check_${pool}.txt" "${mountpoint}/tmp/"
      cp "/tmp/update_crypttab_${pool}.sh" "${mountpoint}/tmp/"
      chroot "${mountpoint}" /bin/bash -x "/tmp/update_crypttab_${pool}.sh"
      ;;
    base)
      if grep -q casper /proc/cmdline; then
        echo "Live environment present. Reboot into new installation."
        exit 1
      fi
      /bin/bash "/tmp/update_crypttab_${pool}.sh"
      ;;
    *)
      exit 1
      ;;
  esac
}



#######################################
# Prepare disks and partitions for ZFS installation.
# Globals:
#   debian_priority
#   efi_boot_size
#   install_warning_level
#   topology_root
#   zfs_root_encrypt
#   zfs_root_password
#   diskid
#   swap_size
# Arguments:
#  None
#######################################
function prepare_install_environment() {
  export debian_priority="${install_warning_level#*=}"

  # Ensure required tools are available from live environment
  if ! command -v sgdisk &>/dev/null; then
    echo "ERROR: gdisk/sgdisk not found. Required for partitioning."
    exit 1
  fi

  if ! command -v zpool &>/dev/null; then
    echo "ERROR: ZFS tools not found in live environment."
    exit 1
  fi

  keyboard_console_settings

  if systemctl is-active --quiet zfs-zed 2>/dev/null; then
    systemctl stop zfs-zed
  fi

  clear_partition_table "root"
  partprobe
  sleep 2

  # Create partitions
  local swap_hex_code root_hex_code

  case "${topology_root}" in
    single|mirror)
      swap_hex_code="8200"
      ;;
    raid0|raidz*)
      swap_hex_code="FD00"
      ;;
  esac

  if [[ -n "${zfs_root_password}" ]]; then
    case "${zfs_root_encrypt}" in
      native)
        root_hex_code="BF00"
        ;;
      luks)
        root_hex_code="FD00"
        ;;
    esac
  else
    root_hex_code="BF00"
  fi

  while IFS= read -r diskid; do
    echo "Creating partitions on disk ${diskid}."
    sgdisk -n1:1M:+"${efi_boot_size}"M -t1:EF00 "/dev/disk/by-id/${diskid}"
    sgdisk -n2:0:+"${swap_size}"M -t2:"${swap_hex_code}" "/dev/disk/by-id/${diskid}"
    sgdisk -n3:0:0 -t3:"${root_hex_code}" "/dev/disk/by-id/${diskid}"
  done < "/tmp/diskid_check_root.txt"

  partprobe
  sleep 2
}

#######################################
# Create root ZFS pool and filesystem datasets.
# Globals:
#   mountpoint
#   rootzfs_full_name
#   rpool
# Arguments:
#  None
#######################################
function create_zfs_pools() {
  create_zpool "root"

  partprobe
  sleep 2

  # Create filesystem datasets
  zfs create -o canmount=off -o mountpoint=none "${rpool}/ROOT"

  rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
  zfs create -o canmount=noauto -o mountpoint=/ "${rpool}/ROOT/${rootzfs_full_name}"
  zfs mount "${rpool}/ROOT/${rootzfs_full_name}"
  zpool set bootfs="${rpool}/ROOT/${rootzfs_full_name}" "${rpool}"

  # Create system datasets
  zfs create "${rpool}/srv"
  zfs create -o canmount=off "${rpool}/usr"
  zfs create "${rpool}/usr/local"
  zfs create -o canmount=off "${rpool}/var"
  zfs create -o canmount=off "${rpool}/var/lib"
  zfs create "${rpool}/var/games"
  zfs create "${rpool}/var/log"
  zfs create "${rpool}/var/mail"
  zfs create "${rpool}/var/snap"
  zfs create "${rpool}/var/spool"
  zfs create "${rpool}/var/www"

  # User data datasets
  zfs create "${rpool}/home"
  zfs create -o mountpoint=/root "${rpool}/home/root"
  chmod 700 "${mountpoint}/root"

  # Exclude from snapshots
  zfs create -o com.sun:auto-snapshot=false "${rpool}/var/cache"
  zfs create -o com.sun:auto-snapshot=false "${rpool}/var/tmp"
  chmod 1777 "${mountpoint}/var/tmp"
  zfs create -o com.sun:auto-snapshot=false "${rpool}/var/lib/docker"

  # Mount tmpfs at /run
  mkdir -p "${mountpoint}/run"
  mount -t tmpfs tmpfs "${mountpoint}/run"
}

#######################################
# Extract Ubuntu live filesystem to the ZFS mountpoint.
# Globals:
#   mountpoint
#   squashfs_path
#   squashfs_type
# Arguments:
#  None
#######################################
function extract_live_filesystem() {
  local free_space
  free_space="$(df -k --output=avail "${mountpoint}" | tail -n1)"

  if [[ "${free_space}" -lt 5242880 ]]; then
    echo "Less than 5 GBs free!"
    exit 1
  fi

  echo "Extracting live filesystem to ${mountpoint}..."

  case "${squashfs_type}" in
    mounted)
      # Copy from already-mounted filesystem
      echo "Copying from mounted filesystem at ${squashfs_path}..."
      rsync -aHAXS --info=progress2 "${squashfs_path}/" "${mountpoint}/"
      ;;
    squashfs)
      # Extract squashfs file
      if ! command -v unsquashfs &>/dev/null; then
        echo "Installing squashfs-tools..."
        apt-get install -y squashfs-tools
      fi

      echo "Extracting squashfs from ${squashfs_path}..."
      unsquashfs -f -d "${mountpoint}" "${squashfs_path}"
      ;;
    *)
      echo "ERROR: Unknown squashfs type: ${squashfs_type}"
      exit 1
      ;;
  esac

  echo "Live filesystem extraction complete."

  # Clean up live environment artifacts
  cleanup_live_artifacts
}

# Remove live environment specific files from extracted system
function cleanup_live_artifacts() {
  echo "Cleaning up live environment artifacts..."

  # Remove casper/live-boot artifacts
  rm -f "${mountpoint}/etc/casper.conf"
  rm -rf "${mountpoint}/etc/live"
  rm -f "${mountpoint}/etc/fstab"

  # Create fresh fstab
  cat > "${mountpoint}/etc/fstab" <<-EOF
		# /etc/fstab: static file system information.
		# <file system> <mount point> <type> <options> <dump> <pass>
	EOF

  # Remove live user if exists
  if [[ -d "${mountpoint}/home/kubuntu" ]]; then
    rm -rf "${mountpoint}/home/kubuntu"
  fi
  if [[ -d "${mountpoint}/home/ubuntu" ]]; then
    rm -rf "${mountpoint}/home/ubuntu"
  fi

  # Remove the live-specific packages list
  rm -f "${mountpoint}/etc/apt/sources.list.d/cdrom.list"

  # Remove installer artifacts
  rm -rf "${mountpoint}/var/log/installer"
  rm -f "${mountpoint}/var/lib/dpkg/status-old"

  # Clean apt cache from the live system
  rm -rf "${mountpoint}/var/cache/apt/archives"/*.deb
  rm -rf "${mountpoint}/var/lib/apt/lists"/*

  echo "Cleanup complete."
}



#######################################
# Configure hostname, networking, locale, and timezone.
# Globals:
#   eth_prefix
#   HOSTNAME
#   install_warning_level
#   locale
#   mountpoint
#   timezone
# Arguments:
#  None
#######################################
function system_setup_part1() {
  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		export DEBIAN_PRIORITY="${install_warning_level#*=}"
	EOCHROOT

  echo "${HOSTNAME}" > "${mountpoint}/etc/hostname"
  echo "127.0.1.1       ${HOSTNAME}" >> "${mountpoint}/etc/hosts"

  local eth_interface
  eth_interface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${eth_prefix}*" | head -1)")"

  # Create the netplan config directory if needed
  mkdir -p "${mountpoint}/etc/netplan"

  cat > "${mountpoint}/etc/netplan/01-${eth_interface}.yaml" <<-EOF
		network:
		  version: 2
		  ethernets:
		    ${eth_interface}:
		      dhcp4: yes
	EOF
  chmod 600 "${mountpoint}/etc/netplan/01-${eth_interface}.yaml"

  mount --rbind /dev "${mountpoint}/dev"
  mount --rbind /proc "${mountpoint}/proc"
  mount --rbind /sys "${mountpoint}/sys"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		locale-gen en_US.UTF-8 ${locale}
		echo 'LANG="${locale}"' > /etc/default/locale

		ln -fs /usr/share/zoneinfo/${timezone} /etc/localtime
		dpkg-reconfigure -f noninteractive tzdata
	EOCHROOT
}

#######################################
# Verify essential packages and enable ZFS services.
# Globals:
#   mountpoint
# Arguments:
#  None
#######################################
function system_setup_part2() {
  # Most packages should already be present from the live filesystem
  #   to ensure ZFS tools are properly configured
  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		# Verify essential packages are present
		if ! dpkg -l linux-image-generic &>/dev/null; then
		  echo "ERROR: linux-image-generic not found in extracted filesystem"
		  exit 1
		fi

		if ! dpkg -l zfsutils-linux &>/dev/null; then
		  echo "ERROR: zfsutils-linux not found in extracted filesystem"
		  exit 1
		fi

		# Ensure ZFS services are enabled
		systemctl enable zfs-import-cache.service || true
		systemctl enable zfs-import.target || true
		systemctl enable zfs-mount.service || true
		systemctl enable zfs.target || true
	EOCHROOT
}

#######################################
# Set up EFI partitions and install rEFInd boot manager.
# Globals:
#   initial_boot_order
#   mountpoint
#   timeout_refind
#   diskid
# Arguments:
#  None
#######################################
function system_setup_part3() {
  identify_ubuntu_dataset_uuid

  apt-get install --yes dosfstools

  local loop_counter=0
  local initial_boot_order

  while IFS= read -r diskid; do
    local esp_mount
    if [[ "${loop_counter}" -eq 0 ]]; then
      esp_mount="/boot/efi"
    else
      esp_mount="/boot/efi${loop_counter}"
      echo "${esp_mount}" >> "${mountpoint}/tmp/backup_esp_mounts.txt"
    fi

    echo "Creating FAT32 filesystem on ${diskid}. ESP: ${esp_mount}"
    umount -q "/dev/disk/by-id/${diskid}-part1" || true
    mkdosfs -F 32 -s 1 -n EFI "/dev/disk/by-id/${diskid}-part1"
    partprobe
    sleep 2

    local blkid_part1
    blkid_part1="$(blkid -s UUID -o value "/dev/disk/by-id/${diskid}-part1")"
    echo "${blkid_part1}" >> /tmp/esp_partition_list_uuid.txt

    chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
			mkdir -p "${esp_mount}"
			echo "/dev/disk/by-uuid/${blkid_part1} ${esp_mount} vfat defaults 0 0" >> /etc/fstab
			mount "${esp_mount}"

			if ! grep -q "${esp_mount}" /proc/mounts; then
			  echo "${esp_mount} not mounted."
			  exit 1
			fi
		EOCHROOT

    ((loop_counter++))
  done < "/tmp/diskid_check_root.txt"

  initial_boot_order="$(efibootmgr | grep "BootOrder" | cut -d " " -f 2)"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		apt-get -yq install refind kexec-tools
		apt-get install --yes dpkg-dev git systemd-sysv

		sed -i 's,^timeout .*,timeout ${timeout_refind},' /boot/efi/EFI/refind/refind.conf

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec
	EOCHROOT
}

#######################################
# Configure ZFS encryption keys and install ZFSBootMenu.
# Globals:
#   mountpoint
#   quiet_boot
#   remoteaccess_first_boot
#   rpool
#   timeout_zbm_no_remote
#   zfs_root_encrypt
#   zfs_root_password
# Arguments:
#  None
#######################################
function system_setup_part4() {
  cp "/tmp/diskid_check_root.txt" "${mountpoint}/tmp/"

  if [[ -f "/tmp/luks_dmname_root.txt" ]]; then
    cp "/tmp/luks_dmname_root.txt" "${mountpoint}/tmp/"
  fi

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		if [[ -n "${zfs_root_password}" ]]; then
		  case "${zfs_root_encrypt}" in
		    native)
		      echo "${zfs_root_password}" > /etc/zfs/${rpool}.key
		      chmod 600 /etc/zfs/${rpool}.key
		      zfs change-key -o keylocation=file:///etc/zfs/${rpool}.key \
		        -o keyformat=passphrase ${rpool}
		      zfs set org.zfsbootmenu:keysource="${rpool}/ROOT" ${rpool}
		      ;;
		    luks)
		      mkdir -p /etc/cryptsetup-keys.d/
		      dd if=/dev/urandom of=/etc/cryptsetup-keys.d/${rpool}.key bs=1024 count=4
		      chmod 600 /etc/cryptsetup-keys.d/${rpool}.key
		      ;;
		  esac
		fi

		echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf
	EOCHROOT

  if [[ "${zfs_root_encrypt}" == "luks" ]]; then
    update_crypttab "chroot" "root"
  fi

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		if [[ "${quiet_boot}" == "yes" ]]; then
		  zfs set org.zfsbootmenu:commandline="spl_hostid=\$(hostid) ro quiet" "${rpool}/ROOT"
		else
		  zfs set org.zfsbootmenu:commandline="spl_hostid=\$(hostid) ro" "${rpool}/ROOT"
		fi
	EOCHROOT

  zfsbootmenu_install_config "chroot"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		cat > /boot/efi/EFI/ubuntu/refind_linux.conf <<-EOF
			"Boot default"  "zbm.timeout=${timeout_zbm_no_remote} ro quiet loglevel=0"
			"Boot to menu"  "zbm.show ro quiet loglevel=0"
		EOF

		if [[ "${quiet_boot}" == "no" ]]; then
		  sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf
		fi
	EOCHROOT

  # Handle multiple ESPs
  local topology
  topology="$(cat /tmp/topology_pool_pointer.txt)"

  if [[ "${topology}" != "single" ]]; then
    zbm_multiple_esp
  fi

  if [[ "${remoteaccess_first_boot}" == "yes" ]]; then
    remote_zbm_access "chroot"
  fi
}

#######################################
# Set root password and configure swap partitions.
# Globals:
#   disks_root
#   mountpoint
#   password
#   topology_root
#   zfs_root_password
# Arguments:
#  None
#######################################
function system_setup_part5() {
  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		echo "root:${password}" | chpasswd -c SHA256
	EOCHROOT

  # Configure swap
  local crypttab_params="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

  case "${topology_root}" in
    single)
      local diskid
      diskid="$(cat /tmp/diskid_check_root.txt)"
      if [[ -n "${zfs_root_password}" ]]; then
        chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
					apt-get install --yes cryptsetup
					echo "swap /dev/disk/by-id/${diskid}-part2 ${crypttab_params}" >> /etc/crypttab
					echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
				EOCHROOT
      else
        chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
					mkswap -f "/dev/disk/by-id/${diskid}-part2"
					blkid_part2="\$(blkid -s UUID -o value /dev/disk/by-id/${diskid}-part2)"
					echo "/dev/disk/by-uuid/\${blkid_part2} none swap defaults 0 0" >> /etc/fstab
					sleep 2
					swapon -a
				EOCHROOT
      fi
      ;;
    mirror)
      mdadm_swap "mirror" "${disks_root}"
      ;;
    raid0)
      configure_raid0_swap
      ;;
    raidz1)
      mdadm_swap "5" "${disks_root}"
      ;;
    raidz2|raidz3)
      mdadm_swap "6" "${disks_root}"
      ;;
  esac

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		cp /usr/share/systemd/tmp.mount /etc/systemd/system/
		systemctl enable tmp.mount

		addgroup --system lpadmin
		addgroup --system lxd
		addgroup --system sambashare

		update-initramfs -c -k all
	EOCHROOT
}

# Configure RAID0 swap (kernel stripe swapping)
function configure_raid0_swap() {
  local loop_counter=0
  local crypttab_params="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

  while IFS= read -r diskid; do
    local swap_name="swap${loop_counter}"

    if [[ -n "${zfs_root_password}" ]]; then
      echo "${swap_name} /dev/disk/by-id/${diskid}-part2 ${crypttab_params}" >> "${mountpoint}/etc/crypttab"
      echo "/dev/mapper/${swap_name} none swap defaults,pri=1 0 0" >> "${mountpoint}/etc/fstab"
    else
      mkswap -f "/dev/disk/by-id/${diskid}-part2"
      local blkid_part2
      blkid_part2="$(blkid -s UUID -o value "/dev/disk/by-id/${diskid}-part2")"
      echo "/dev/disk/by-uuid/${blkid_part2} none swap defaults,pri=1 0 0" >> "${mountpoint}/etc/fstab"
    fi

    ((loop_counter++))
  done < "/tmp/diskid_check_root.txt"
}

# Configure MDADM swap for mirror/raidz
function mdadm_swap() {
  local mdadm_level="$1"
  local mdadm_devices="$2"
  local mdadm_swap_loc="/tmp/multi_disc_swap.sh"
  local crypttab_params="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

  cat > "${mdadm_swap_loc}" <<-EOF
		#!/bin/bash
		apt-get install --yes mdadm

		mdadm --create /dev/md0 --metadata=1.2 \\
		  --level=${mdadm_level} \\
		  --raid-devices=${mdadm_devices} \\
	EOF

  while IFS= read -r diskid; do
    echo "  /dev/disk/by-id/${diskid}-part2 \\" >> "${mdadm_swap_loc}"
  done < "/tmp/diskid_check_root.txt"

  sed -i '$ s/ \\$//' "${mdadm_swap_loc}"

  if [[ -n "${zfs_root_password}" ]]; then
    cat >> "${mdadm_swap_loc}" <<-EOF

			apt-get install --yes cryptsetup
			echo "swap /dev/md0 ${crypttab_params}" >> /etc/crypttab
			echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
		EOF
  else
    cat >> "${mdadm_swap_loc}" <<-EOF

			mkswap -f /dev/md0
			blkid_md0="\$(blkid -s UUID -o value /dev/md0)"
			echo "/dev/disk/by-uuid/\${blkid_md0} none swap defaults 0 0" >> /etc/fstab
		EOF
  fi

  cat >> "${mdadm_swap_loc}" <<-EOF

		mdadm --detail --scan --verbose | tee -a /etc/mdadm/mdadm.conf
		cat /proc/mdstat
		mdadm --detail /dev/md0
	EOF

  cp "${mdadm_swap_loc}" "${mountpoint}/tmp/"
  chroot "${mountpoint}" /bin/bash -x "${mdadm_swap_loc}"
}



#######################################
# Install and configure ZFSBootMenu from source.
# Globals:
#   mountpoint
#   quiet_boot
#   zfs_root_encrypt
#   zfs_root_password
# Arguments:
#   $1 - Script environment: "chroot" or "base"
#######################################
function zfsbootmenu_install_config() {
  local script_env="$1"
  local zfsbootmenu_script="/tmp/zfsbootmenu_install_config.sh"

  cat > "${zfsbootmenu_script}" <<-'EOSCRIPT'
		#!/bin/bash
		set -euo pipefail

		apt-get update
		apt-get install --yes bsdextrautils mbuffer
		apt-get install --yes --no-install-recommends \
		  libsort-versions-perl \
		  libboolean-perl \
		  libyaml-pp-perl \
		  git \
		  fzf \
		  make \
		  kexec-tools \
		  dracut-core \
		  cpio \
		  curl

		mkdir -p /usr/local/src/zfsbootmenu
		cd /usr/local/src/zfsbootmenu

		git clone https://github.com/zbm-dev/zfsbootmenu .
		make core dracut

		# Configure ZFSBootMenu
		kb_layoutcode="$(debconf-get-selections | grep keyboard-configuration/layoutcode | awk '{print $4}')"

		sed \
		  -e 's,ManageImages:.*,ManageImages: true,' \
		  -e 's@ImageDir:.*@ImageDir: /boot/efi/EFI/ubuntu@' \
		  -e 's,Versions:.*,Versions: false,' \
		  -e "/CommandLine/s,ro,rd.vconsole.keymap=${kb_layoutcode} ro," \
		  -i /etc/zfsbootmenu/config.yaml
	EOSCRIPT

  # Add quiet boot handling
  if [[ "${quiet_boot}" == "no" ]]; then
    cat >> "${zfsbootmenu_script}" <<-'EOF'

			sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
		EOF
  fi

  # Add LUKS hook if needed
  if [[ -n "${zfs_root_password}" && "${zfs_root_encrypt}" == "luks" ]]; then
    cat >> "${zfsbootmenu_script}" <<-'EOF'

			zfsbootmenu_hook_root="/etc/zfsbootmenu/hooks"
			mkdir -p "${zfsbootmenu_hook_root}/early-setup.d"
			cd "${zfsbootmenu_hook_root}/early-setup.d"
			curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/hooks/early-setup.d/luks-unlock.sh
			chmod +x "${zfsbootmenu_hook_root}/early-setup.d/luks-unlock.sh"

			cd /etc/zfsbootmenu/dracut.conf.d/
			curl -L -O https://raw.githubusercontent.com/agorgl/zbm-luks-unlock/master/dracut.conf.d/99-crypt.conf
		EOF
  fi

  cat >> "${zfsbootmenu_script}" <<-'EOF'

		update-initramfs -c -k all
		generate-zbm --debug
	EOF

  case "${script_env}" in
    chroot)
      cp "${zfsbootmenu_script}" "${mountpoint}/tmp/"
      chroot "${mountpoint}" /bin/bash -x "${zfsbootmenu_script}"
      ;;
    base)
      /bin/bash "${zfsbootmenu_script}"
      ;;
    *)
      exit 1
      ;;
  esac
}

# Configure multiple ESPs for redundancy
function zbm_multiple_esp() {
  local esp_sync_path="/etc/zfsbootmenu/generate-zbm.post.d/esp-sync.sh"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		mkdir -p "/etc/zfsbootmenu/generate-zbm.post.d/"

		cat > "${esp_sync_path}" <<-'EOT'
			#!/bin/bash
			sync_func() {
			  rsync --delete-after -axHAWXS --info=progress2 /boot/efi/ "\$1"
			}
		EOT

		while IFS= read -r esp_mount; do
		  echo "sync_func \"\${esp_mount}\"" >> "${esp_sync_path}"
		done < /tmp/backup_esp_mounts.txt

		chmod +x "${esp_sync_path}"
		apt-get install -y rsync
		sh "${esp_sync_path}"
	EOCHROOT

  # Add backup ESPs to EFI boot manager
  local loop_counter=0
  while IFS= read -r diskid; do
    if [[ "${loop_counter}" -gt 0 ]]; then
      local device_name
      device_name="$(readlink -f "/dev/disk/by-id/${diskid}")"
      efibootmgr --create --disk "${device_name}" \
        --label "rEFInd Boot Manager Backup ${loop_counter}" \
        --loader "\\EFI\\refind\\refind_x64.efi"
    fi
    ((loop_counter++))
  done < "/tmp/diskid_check_root.txt"

  # Adjust ESP boot order
  local primary_esp_hex
  primary_esp_hex="$(efibootmgr | grep -v "Backup" | grep -w "rEFInd Boot Manager" | \
    cut -d " " -f 1 | sed 's,Boot,,' | sed 's,\*,,')"

  local primary_esp_dec
  primary_esp_dec="$(printf "%d" "0x${primary_esp_hex}")"

  local num_disks
  num_disks="$(wc -l < /tmp/diskid_check_root.txt)"

  local revised_order="${primary_esp_hex}"
  for ((i = primary_esp_dec + 1; i < primary_esp_dec + num_disks; i++)); do
    revised_order="${revised_order},$(printf "%04X" "${i}")"
  done
  revised_order="${revised_order},${initial_boot_order}"

  efibootmgr -o "${revised_order}"
}

# Remote access to ZFSBootMenu via SSH
# bashsupport disable=SpellCheckingInspection
function remote_zbm_access() {
  local script_env="$1"

  cat > /tmp/remote_zbm_access.sh <<-EOSCRIPT
		#!/bin/bash
		set -euo pipefail

		apt-get update
		apt-get install -y dracut-network dropbear isc-dhcp-client

		# Configure dracut crypt-ssh module
		git -C /tmp clone 'https://github.com/dracut-crypt-ssh/dracut-crypt-ssh.git'
		mkdir -p /usr/lib/dracut/modules.d/60crypt-ssh
		cp /tmp/dracut-crypt-ssh/modules/60crypt-ssh/* /usr/lib/dracut/modules.d/60crypt-ssh/
		rm -f /usr/lib/dracut/modules.d/60crypt-ssh/Makefile

		modulesetup="/usr/lib/dracut/modules.d/60crypt-ssh/module-setup.sh"

		sed -i \\
		  -e 's,  inst "\$moddir"/helper/console_auth /bin/console_auth,  #inst "\$moddir"/helper/console_auth /bin/console_auth,' \\
		  -e 's,  inst "\$moddir"/helper/console_peek.sh /bin/console_peek,  #inst "\$moddir"/helper/console_peek.sh /bin/console_peek,' \\
		  -e 's,  inst "\$moddir"/helper/unlock /bin/unlock,  #inst "\$moddir"/helper/unlock /bin/unlock,' \\
		  -e 's,  inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,  #inst "\$moddir"/helper/unlock-reap-success.sh /sbin/unlock-reap-success,' \\
		  "\${modulesetup}"

		# Setup network
		mkdir -p /etc/cmdline.d

		case "${remoteaccess_ip_config}" in
		  dhcp|dhcp,dhcp6|dhcp6)
		    echo "ip=${remoteaccess_ip_config} rd.neednet=1" > /etc/cmdline.d/dracut-network.conf
		    ;;
		  static)
		    echo "ip=${remoteaccess_ip}:::${remoteaccess_netmask}:::none rd.neednet=1 rd.break" > /etc/cmdline.d/dracut-network.conf
		    ;;
		esac

		echo 'send fqdn.fqdn "${remoteaccess_hostname}";' >> /usr/lib/dracut/modules.d/35network-legacy/dhclient.conf

		# Welcome message
		cat > /etc/zfsbootmenu/dracut.conf.d/banner.txt <<-EOF
			Welcome to ZFSBootMenu. Enter "zfsbootmenu" or "zbm" to start.
		EOF
		chmod 755 /etc/zfsbootmenu/dracut.conf.d/banner.txt

		sed -i 's,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid,  /sbin/dropbear -s -j -k -p \${dropbear_port} -P /tmp/dropbear.pid -b /etc/banner.txt,' \\
		  /usr/lib/dracut/modules.d/60crypt-ssh/dropbear-start.sh

		sed -i '\$ s,^},,' "\${modulesetup}"
		echo '  inst /etc/zfsbootmenu/dracut.conf.d/banner.txt /etc/banner.txt' >> "\${modulesetup}"
		echo '}' >> "\${modulesetup}"

		# Create host keys
		mkdir -p /etc/dropbear
		for keytype in rsa ecdsa ed25519; do
		  ssh-keygen -t "\${keytype}" -m PEM -f "/etc/dropbear/ssh_host_\${keytype}_key" -N ""
		done

		sed -i '/inst "\${dropbear_acl}"/a \\  chown root:root "\${initdir}/root/.ssh/authorized_keys"' "\${modulesetup}"

		# Dropbear configuration
		cat > /etc/zfsbootmenu/dracut.conf.d/dropbear.conf <<-EOF
			add_dracutmodules+=" crypt-ssh network-legacy "
			install_optional_items+=" /etc/cmdline.d/dracut-network.conf "
			dropbear_rsa_key="/etc/dropbear/ssh_host_rsa_key"
			dropbear_ecdsa_key="/etc/dropbear/ssh_host_ecdsa_key"
			dropbear_ed25519_key="/etc/dropbear/ssh_host_ed25519_key"
			#dropbear_acl="/home/${new_user}/.ssh/authorized_keys"
		EOF

		systemctl stop dropbear || true
		systemctl disable dropbear || true

		sed -i 's,zbm.timeout=${timeout_zbm_no_remote},zbm.timeout=${timeout_zbm_remote},' /boot/efi/EFI/ubuntu/refind_linux.conf

		generate-zbm --debug
	EOSCRIPT

  case "${script_env}" in
    chroot)
      cp /tmp/remote_zbm_access.sh "${mountpoint}/tmp/"
      chroot "${mountpoint}" /bin/bash -x /tmp/remote_zbm_access.sh
      ;;
    base)
      if grep -q casper /proc/cmdline; then
        echo "Live environment present. Reboot into new installation."
        exit 1
      fi

      /bin/bash /tmp/remote_zbm_access.sh

      sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
      mkdir -p "/home/${new_user}/.ssh"
      chown "${new_user}:${new_user}" "/home/${new_user}/.ssh"
      touch "/home/${new_user}/.ssh/authorized_keys"
      chmod 644 "/home/${new_user}/.ssh/authorized_keys"
      chown "${new_user}:${new_user}" "/home/${new_user}/.ssh/authorized_keys"

      echo "ZFSBootMenu remote access installed."
      echo "Connect as root on port 222: ssh root@{IP} -p 222"
      echo "Add your SSH public key to /home/${new_user}/.ssh/authorized_keys"
      echo "Then run: sudo generate-zbm"
      ;;
    *)
      exit 1
      ;;
  esac
}



#######################################
# Create user account and home directory datasets.
# Globals:
#   mountpoint
#   new_user
#   password
#   rpool
# Arguments:
#  None
#######################################
function user_setup() {
  zfs create -o mountpoint="/home/${new_user}" "${rpool}/home/${new_user}"
  zfs create -o compression=off "${rpool}/home/${new_user}/Videos"
  zfs create -o compression=off "${rpool}/home/${new_user}/Downloads"
  zfs create -o compression=off "${rpool}/home/${new_user}/Music"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		adduser --disabled-password --gecos "" "${new_user}"
		cp -a /etc/skel/. "/home/${new_user}"
		chown -R "${new_user}:${new_user}" "/home/${new_user}"
		usermod -a -G adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "${new_user}"
		echo "${new_user}:${password}" | chpasswd

		cat > /etc/sudoers.d/99-nopasswd-apt <<-EOSUDOERS
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/apt
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/apt-get
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/apt-cache
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/dpkg
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/snap
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/flatpak
			${new_user} ALL=(ALL) NOPASSWD: /usr/bin/plasma-discover
			${new_user} ALL=(ALL) NOPASSWD: /usr/lib/x86_64-linux-gnu/libexec/discover/DiscoverNotifier
			${new_user} ALL=(ALL) NOPASSWD: /usr/libexec/packagekitd
		EOSUDOERS
		chmod 440 /etc/sudoers.d/99-nopasswd-apt
	EOCHROOT
}

#######################################
# Update system packages and configure display manager.
# Globals:
#   debian_priority
#   distro_variant
#   install_warning_level
#   mirror_archive
#   rpool
# Arguments:
#  None
#######################################
function distro_install() {
  # Desktop already installed from squashfs, just update and ensure packages
  export debian_priority="${install_warning_level#*=}"

  if [[ -n "${mirror_archive}" ]]; then
    apt_mirror_source
  fi

  apt-get update
  apt-get dist-upgrade --yes

  # Create AccountsService dataset for desktop variants
  if [[ "${distro_variant}" != "server" ]]; then
    if ! zfs list "${rpool}/var/lib/AccountsService" &>/dev/null; then
      zfs create "${rpool}/var/lib/AccountsService"
    fi
  fi

  # Ensure the correct display manager is set
  case "${distro_variant}" in
    server)
      # Server variant - no display manager needed
      ;;
    desktop|kubuntu)
      echo "sddm shared/default-x-display-manager select sddm" | debconf-set-selections
      dpkg-reconfigure -f noninteractive sddm || true
      ;;
    xubuntu|budgie|MATE)
      echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections
      dpkg-reconfigure -f noninteractive lightdm || true
      ;;
    *)
      echo "Ubuntu variant not recognised."
      exit 1
      ;;
  esac
}

#######################################
# Switch from netplan to NetworkManager for desktop.
# Globals:
#   eth_prefix
# Arguments:
#  None
# Returns:
#   0 if NetworkManager is not installed
#######################################
function network_manager_config() {
  if ! dpkg-query --show --showformat='${db:Status-Status}\n' "network-manager" 2>/dev/null | grep -q "installed"; then
    return 0
  fi

  local eth_interface
  eth_interface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${eth_prefix}*" | head -1)")"

  rm -f "/etc/netplan/01-${eth_interface}.yaml"

  cat > /etc/netplan/01-network-manager-all.yaml <<-EOF
		network:
		  version: 2
		  renderer: NetworkManager
	EOF

  systemctl stop systemd-networkd
  systemctl disable systemd-networkd
  netplan apply
}

#######################################
# Install and configure Sanoid for ZFS snapshot management.
# Globals:
#   rpool
# Arguments:
#  None
#######################################
function sanoid_install() {
  apt-get update
  apt-get install -y sanoid

  mkdir -p /etc/sanoid

  cat > /etc/sanoid/sanoid.conf <<-EOF
		[${rpool}/ROOT]
		  use_template = template_production
		  recursive = yes
		  process_children_only = yes

		[template_production]
		  frequently = 4
		  hourly = 24
		  daily = 7
		  weekly = 4
		  monthly = 6
		  yearly = 0
		  autosnap = yes
		  autoprune = yes
	EOF

  # Pre-apt snapshot hook
  local pre_apt_prefix="pre-apt"

  cat > /etc/apt/apt.conf.d/80-zfs-snapshot <<-EOF
		DPkg::Pre-Invoke { "echo 'Creating ZFS snapshot.'; ts=${pre_apt_prefix}_\$(date +%F_%H:%M:%S); zfs snapshot -r ${rpool}/ROOT@\${ts} && zfs destroy ${rpool}/ROOT@\${ts} || true"; };
	EOF

  cat > /usr/local/bin/apt-snapshot-prune.sh <<-'EOF'
		#!/bin/bash
		zfs list -H -p -o name,creation -t snapshot -r $(zpool list -H -o name) | grep 'pre-apt' |
		while read -r name creation; do
		  age=$(( $(date +%s) - creation ))
		  one_week=$(( 7 * 24 * 3600 ))
		  if [[ ${age} -gt ${one_week} ]]; then
		    echo "Deleting old snapshot: ${name}"
		    zfs destroy "${name}"
		  fi
		done
	EOF
  chmod +x /usr/local/bin/apt-snapshot-prune.sh

  cat > /etc/systemd/system/apt-snapshot-prune.service <<-EOF
		[Unit]
		Description=Prune old pre-apt ZFS snapshots

		[Service]
		Type=oneshot
		ExecStart=/usr/local/bin/apt-snapshot-prune.sh
		Nice=19
		IOSchedulingClass=3
	EOF

  cat > /etc/systemd/system/apt-snapshot-prune.timer <<-EOF
		[Unit]
		Description=Daily cleanup of old pre-apt ZFS snapshots
		Requires=apt-snapshot-prune.service

		[Timer]
		OnCalendar=daily
		Persistent=true
		Unit=apt-snapshot-prune.service

		[Install]
		WantedBy=timers.target
	EOF

  /usr/sbin/sanoid --take-snapshots --verbose
  systemctl enable --now sanoid.timer
}

#######################################
# Install optional utility programs (SSH, CIFS, man pages).
# Globals:
#   extra_programs
# Arguments:
#  None
# Returns:
#   0 if extra_programs is not "yes"
#######################################
function extra_programs_install() {
  if [[ "${extra_programs}" != "yes" ]]; then
    return 0
  fi

  apt-get install -yq cifs-utils
  apt-get install -y openssh-server
  apt-get install --yes man-db tldr locate
}

#######################################
# Disable log compression since ZFS handles compression.
# Globals:
#   mountpoint
# Arguments:
#  None
#######################################
function log_compress_disable() {
  chroot "${mountpoint}" /bin/bash -x <<-'EOCHROOT'
		for file in /etc/logrotate.d/*; do
		  if grep -Eq "(^|[^#y])compress" "${file}"; then
		    sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "${file}"
		  fi
		done
	EOCHROOT
}

#######################################
# Apply saved keyboard and console settings to new system.
# Globals:
#   kb_console_settings
#   mountpoint
# Arguments:
#  None
#######################################
function keyboard_console_setup() {
  cp "${kb_console_settings}" "${mountpoint}/tmp/"

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		apt-get install -y debconf-utils
		debconf-set-selections < "/tmp/$(basename "${kb_console_settings}")"
		rm -f /etc/default/keyboard
		dpkg-reconfigure -f noninteractive keyboard-configuration
		dpkg-reconfigure -f noninteractive console-setup
	EOCHROOT
}

#######################################
# Configure ZFS mount ordering via zfs-list.cache.
# Globals:
#   mountpoint
#   rootzfs_full_name
#   rpool
# Arguments:
#  None
#######################################
function fix_fs_mount_order() {
  identify_ubuntu_dataset_uuid

  chroot "${mountpoint}" /bin/bash -x <<-EOCHROOT
		mkdir -p /etc/zfs/zfs-list.cache
		touch "/etc/zfs/zfs-list.cache/${rpool}"

		zed -F &
		sleep 2

		while [[ ! -s "/etc/zfs/zfs-list.cache/${rpool}" ]]; do
		  zfs set canmount=noauto "${rpool}/ROOT/${rootzfs_full_name}"
		  sleep 1
		done

		pkill -9 "zed" || true
		sleep 2

		sed -Ei "s|${mountpoint}/?|/|" "/etc/zfs/zfs-list.cache/${rpool}"
	EOCHROOT
}

#######################################
# Unmount all filesystems under the mountpoint.
# Globals:
#   mountpoint
# Arguments:
#  None
#######################################
function unmount_datasets() {
  mount --make-rslave "${mountpoint}/dev"
  mount --make-rslave "${mountpoint}/proc"
  mount --make-rslave "${mountpoint}/sys"

  grep "${mountpoint}" /proc/mounts | cut -f2 -d" " | sort -r | xargs -r umount -n
}



#######################################
# Create a separate ZFS data pool on non-root disks.
# Globals:
#   datapool
#   datapool_mount
#   new_user
#   rpool
#   zfs_data_encrypt
#   zfs_data_password
#   _
# Arguments:
#  None
#######################################
function create_data_pool() {
  local _
  disclaimer

  if zpool status "${datapool}" &>/dev/null; then
    echo "Warning: ${datapool} already exists. Continue to destroy it?"
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
  fi

  if [[ -n "${zfs_data_password}" ]]; then
    echo "Warning: Data pool will use root pool keyfile for auto-unlock."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
  fi

  get_disk_id_pool "data"
  clear_partition_table "data"
  partprobe
  sleep 2

  if [[ ! -d "${datapool_mount}" ]]; then
    mkdir -p "${datapool_mount}"
    chown "${new_user}:${new_user}" "${datapool_mount}"
  fi

  touch "/etc/zfs/zfs-list.cache/${datapool}"

  create_zpool "data"

  if [[ "${zfs_data_encrypt}" == "luks" ]]; then
    if [[ -f "/etc/cryptsetup-keys.d/${rpool}.key" ]]; then
      update_crypttab "base" "data"
    else
      echo "${rpool}.key not found."
      exit 1
    fi
  fi

  while [[ ! -s "/etc/zfs/zfs-list.cache/${datapool}" ]]; do
    zfs set canmount=on "${datapool}"
    sleep 1
  done

  ln -s "${datapool_mount}" "/home/${new_user}/"
  chown -R "${new_user}:${new_user}" "${datapool_mount}" "/home/${new_user}/${datapool}"

  zpool status
  zfs list
}



#######################################
# Reinstall or update ZFSBootMenu to latest version.
# Globals:
#   choice
# Arguments:
#  None
#######################################
function reinstall_zbm() {
  local choice
  disclaimer
  connectivity_check

  if grep -q casper /proc/cmdline; then
    echo "Live environment present. Reboot into new installation."
    exit 1
  fi

  if ! command -v generate-zbm &>/dev/null; then
    echo "Please install zfsbootmenu first."
    exit 1
  fi

  local zbm_latest
  zbm_latest="$(curl -s https://api.github.com/repos/zbm-dev/zfsbootmenu/releases/latest | \
    grep tag_name | cut -d : -f 2,3 | tr -d '\" ,' | sed 's,^v,,')"

  echo "Latest ZFSBootMenu version: ${zbm_latest}"

  local zbm_installed
  zbm_installed="$(generate-zbm --showver 2>/dev/null || echo "unknown")"
  echo "Installed version: ${zbm_installed}"

  if [[ "${zbm_latest}" == "${zbm_installed}" ]]; then
    echo "Already at latest version. Reinstall anyway? (Y/N)"
    read -r choice
    if [[ "${choice,,}" != "y" ]]; then
      echo "Exiting."
      exit 0
    fi
  fi

  zfsbootmenu_install_config "base"
}

#######################################
# Run complete initial Ubuntu on ZFS installation.
# Globals:
#   new_user
#   password
# Arguments:
#  None
#######################################
function initial_install() {
  disclaimer
  live_desktop_check
  locate_squashfs
  get_disk_id_pool "root"

  prepare_install_environment
  create_zfs_pools
  extract_live_filesystem
  system_setup_part1
  system_setup_part2
  system_setup_part3
  keyboard_console_setup
  system_setup_part4
  system_setup_part5
  user_setup
  log_compress_disable
  script_copy
  fix_fs_mount_order
  log_copy

  echo "Initial setup complete."
  echo "Reboot required."
  echo "First login: ${new_user}:${password}"
  echo "After reboot, run script with 'postreboot' option."
}

#######################################
# Complete installation after first reboot into new system.
# Globals:
#   distro_variant
#   _
# Arguments:
#  None
#######################################
function post_reboot() {
  local _
  disclaimer

  # Check internet connectivity for post-reboot operations
  echo "Checking internet connectivity..."
  if ! nc -zw5 "google.com" 443 2>/dev/null; then
    echo "WARNING: No internet connectivity detected."
    echo "Post-reboot setup requires internet for updates and additional packages."
    echo "Press Enter to continue anyway or CTRL+C to abort."
    read -r _
  fi

  distro_install
  network_manager_config
  sanoid_install
  extra_programs_install

  timedatectl set-local-rtc 1 --adjust-system-clock
  echo "RTC set to local time for Windows dual boot."

  echo "Installation complete: ${distro_variant}."
  echo "Reboot recommended."
}

#######################################
# Install SSH-based remote access to ZFSBootMenu.
# Arguments:
#  None
#######################################
function setup_remote_access() {
  if [[ -f /etc/zfsbootmenu/dracut.conf.d/dropbear.conf ]]; then
    echo "Remote access already installed."
    exit 0
  fi

  disclaimer
  remote_zbm_access "base"
}

#######################################
# Main entry point - parse arguments and dispatch commands.
# Globals:
#   datapool
#   datapool_mount
#   disks_data
#   disks_root
#   distro_variant
#   efi_boot_size
#   eth_prefix
#   extra_programs
#   HOSTNAME
#   install_log
#   install_warning_level
#   locale
#   log_loc
#   mirror_archive
#   mountpoint
#   new_user
#   password
#   quiet_boot
#   remoteaccess_first_boot
#   remoteaccess_hostname
#   remoteaccess_ip
#   remoteaccess_ip_config
#   remoteaccess_netmask
#   rpool
#   timeout_refind
#   timeout_zbm_no_remote
#   timeout_zbm_remote
#   timezone
#   topology_data
#   topology_root
#   ubuntu_original
#   ubuntu_ver
#   zfs_compression
#   zfs_data_encrypt
#   zfs_data_password
#   zfs_dpool_ashift
#   zfs_root_encrypt
#   zfs_root_password
#   zfs_rpool_ashift
#   _
#   swap_size
#   total_ram_mb
# Arguments:
#   $1 - Command: initial, postreboot, remoteaccess, datapool, reinstall-zbm
#######################################
function main() {
# shellcheck disable=SC2317  # Don't warn about unreachable commands
set -euo pipefail

#######################################
# Configuration Variables
#######################################


# Ubuntu release and variant
readonly ubuntu_ver="questing"
# jammy (22.04), noble (24.04), questing (25.10)
readonly distro_variant="kubuntu"
# server, desktop, kubuntu, xubuntu, budgie, MATE


# User account
readonly new_user="me"
readonly password="Willy123$"
readonly HOSTNAME="precision"


# ZFS root pool encryption
readonly zfs_root_password=""
# Minimum 8 chars, empty with no encryption
readonly zfs_root_encrypt="native"

# Locale and timezone
readonly locale="en_US.UTF-8"
readonly timezone="America/New_York"


# ZFS pool settings
readonly zfs_rpool_ashift="12"
# 9=512B, 12=4KiB, 13=8KiB sectors
readonly zfs_compression="zstd"
# lz4 or zstd
readonly mirror_archive=""
# ISO 3166-1 alpha-2 country code or empty


# Root pool configuration
readonly rpool="rpool"
readonly topology_root="raidz1"
# single, mirror, raid0, raidz1, raidz2, raidz3
readonly disks_root="3"
# Number of disks (ignored for single)
readonly efi_boot_size="512"
# EFI partition size in MiB
swap_size=""
# Empty for auto-calculate based on RAM


# Data pool configuration
readonly datapool="datapool"
readonly topology_data="single"
# single, mirror, raid0, raidz1, raidz2, raidz3
# shellcheck disable=SC2034  # Used via indirect reference
local disks_data
readonly disks_data="1"
# Number of disks (ignored for single)
readonly zfs_data_password=""
# Only used if the root pool has no password
readonly zfs_data_encrypt="native"
# native or luks
readonly datapool_mount="/mnt/${datapool}"
readonly zfs_dpool_ashift="12"


# Installation paths
readonly mountpoint="/mnt/ub_server"
readonly install_log="ubuntu_setup_zfs_root.log"
readonly log_loc="/var/log"


# Boot and remote access settings
readonly remoteaccess_first_boot="no"
readonly timeout_refind="3"
readonly timeout_zbm_no_remote="3"
readonly timeout_zbm_remote="45"
readonly quiet_boot="yes"


# Network settings
readonly eth_prefix="e"
readonly remoteaccess_hostname="zbm"
readonly remoteaccess_ip_config="dhcp"
# dhcp, dhcp,dhcp6, dhcp6, or static
readonly remoteaccess_ip="192.168.0.222"
readonly remoteaccess_netmask="255.255.255.0"


# Package sources
readonly ubuntu_original="https://atl.mirrors.clouvider.net/ubuntu/"
readonly install_warning_level="PRIORITY=critical"
# or FRONTEND=noninteractive
readonly extra_programs="yes"


#######################################
# Pre-flight Checks
#######################################


# Check for root privileges
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root."
  exit 1
fi


# Check for EFI boot environment
if [[ -d /sys/firmware/efi ]]; then
  echo "Boot environment check passed. Found EFI boot environment."
else
  echo "Boot environment check failed. EFI boot environment not found."
  exit 1
fi


# Check encryption method is defined if a password is set
if [[ -n "${zfs_root_password}" && -z "${zfs_root_encrypt}" ]]; then
  echo "Password entered but no encryption method defined."
  exit 1
fi


# Auto-calculate swap size based on system RAM if not set
  local total_ram_mb
if [[ -z "${swap_size}" ]]; then
  total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')

  case "${topology_root}" in
    single|mirror)
      swap_size="${total_ram_mb}"
      ;;
    raid0)
      swap_size=$((total_ram_mb / disks_root))
      ;;
    raidz1)
      swap_size=$((total_ram_mb / (disks_root - 1)))
      ;;
    raidz2)
      swap_size=$((total_ram_mb / (disks_root - 2)))
      ;;
    raidz3)
      swap_size=$((total_ram_mb / (disks_root - 3)))
      ;;
  esac

  echo "Auto-calculated swap_size: ${swap_size} MiB per disk"
fi

log_func
date
timedatectl || true
if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
  systemctl restart systemd-timesyncd.service || true
elif systemctl is-active --quiet chrony 2>/dev/null; then
  chronyc burst 4/4 || true
  chronyc makestep || true
fi
timedatectl || true
  local _
case "${1:-}" in
  initial)
    echo "Running initial system installation."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
    initial_install
    ;;
  postreboot)
    echo "Running post-reboot setup."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
    post_reboot
    ;;
  remoteaccess)
    echo "Installing remote access to ZFSBootMenu."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
    setup_remote_access
    ;;
  datapool)
    echo "Creating data pool on non-root drive."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
    create_data_pool
    ;;
  reinstall-zbm)
    echo "Reinstalling ZFSBootMenu."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
    reinstall_zbm
    ;;
  *)
    echo "Usage: $0 {initial|postreboot|remoteaccess|datapool|reinstall-zbm}"
    exit 1
    ;;
esac


date
exit 0
}

main "$@"
