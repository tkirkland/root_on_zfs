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
# Part 1: Run with "initial" option from Ubuntu live ISO (desktop version).
# Part 2: Reboot into new install, login as user/password defined below.
# Part 3: Run with "postreboot" option to complete installation.

# Log all output to file
function log_func() {
  exec > >(tee -a "${LOG_LOC}/${INSTALL_LOG}") 2>&1
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

  # Search for squashfs file
  for path in "${search_paths[@]}"; do
    if [[ -f "${path}" ]]; then
      squashfs_path="${path}"
      squashfs_type="squashfs"
      echo "Found squashfs at ${squashfs_path}"
      return 0
    fi
  done

  # Search mounted filesystems for casper directory
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

  if [[ "${live_version}" != "${UBUNTU_VER,,}" ]]; then
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
  export debian_priority="${INSTALL_WARNING_LEVEL#*=}"

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
    | grep -v "CD-ROM" > "${diskid_menu}"

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
  mirrors=$(curl -s "https://mirrors.ubuntu.com/${MIRROR_ARCHIVE}.txt" | shuf -n 20)

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
  elif [[ "${UBUNTU_ORIGINAL}" != "${ubuntu_mirror}" ]]; then
    cp "${apt_data_sources_loc}" "${apt_data_sources_loc}.non-mirror"
    sed -i "s,${UBUNTU_ORIGINAL},${ubuntu_mirror},g" "${apt_data_sources_loc}"
    echo "Selected '${ubuntu_mirror}'."
  else
    echo "Identified mirror is already selected."
  fi
}

# Copy install log to a new installation
function log_copy() {
  if [[ -d "${MOUNTPOINT}" ]]; then
    cp "${LOG_LOC}/${INSTALL_LOG}" "${MOUNTPOINT}${LOG_LOC}/"
    echo "Log file copied into new installation."
  else
    echo "No mountpoint dir present. Install log not copied."
  fi
}

# Copy script to new installation
function script_copy() {
  cp "$(readlink -f "$0")" "${MOUNTPOINT}/home/${NEW_USER}/"
  local script_loc
  script_loc="/home/${NEW_USER}/$(basename "$0")"

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		chown "${NEW_USER}:${NEW_USER}" "${script_loc}"
		chmod +x "${script_loc}"
	EOCHROOT

  if [[ -f "${MOUNTPOINT}${script_loc}" ]]; then
    echo "Install script copied to new installation."
  else
    echo "Error copying install script."
  fi
}



# Create ZFS pool
function create_zpool() {
  local pool="$1"
  local ashift keylocation zpool_password zpool_encrypt zpool_partition zpool_name topology

  case "${pool}" in
    root)
      ashift="${ZFS_RPOOL_ASHIFT}"
      keylocation="prompt"
      zpool_password="${ZFS_ROOT_PASSWORD}"
      zpool_encrypt="${ZFS_ROOT_ENCRYPT}"
      zpool_partition="-part3"
      zpool_name="${RPOOL}"
      topology="${TOPOLOGY_ROOT}"
      ;;
    data)
      ashift="${ZFS_DPOOL_ASHIFT}"
      zpool_password="${ZFS_DATA_PASSWORD}"
      zpool_encrypt="${ZFS_DATA_ENCRYPT}"
      zpool_partition=""
      zpool_name="${DATAPOOL}"
      topology="${TOPOLOGY_DATA}"

      if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
        case "${ZFS_ROOT_ENCRYPT}" in
          native)
            keylocation="file:///etc/zfs/${RPOOL}.key"
            ;;
          luks)
            keylocation="file:///etc/cryptsetup-keys.d/${RPOOL}.key"
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
  -O compression=${ZFS_COMPRESSION} \\
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
    echo "  -O mountpoint=/ -R ${MOUNTPOINT} \\" >> "${zpool_create_temp}"
  else
    echo "  -O mountpoint=${DATAPOOL_MOUNT} \\" >> "${zpool_create_temp}"
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
    zpool_password="${ZFS_ROOT_PASSWORD}"
    zpool_partition="-part3"
    crypttab_parameters="luks,discard,initramfs"
    ;;
  data)
    zpool_password="${ZFS_DATA_PASSWORD}"
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
    cryptsetup -v luksAddKey "/dev/disk/by-uuid/\${blkid_luks}" "/etc/cryptsetup-keys.d/${RPOOL}.key"

  echo "\${luks_dmname} UUID=\${blkid_luks} /etc/cryptsetup-keys.d/${RPOOL}.key \${crypttab_parameters}" >> /etc/crypttab

  ((loop_counter++))
done < "/tmp/diskid_check_${pool}.txt"

sed -i 's,#KEYFILE_PATTERN=,KEYFILE_PATTERN="/etc/cryptsetup-keys.d/*.key",' \\
  /etc/cryptsetup-initramfs/conf-hook
EOSCRIPT

  case "${script_env}" in
    chroot)
      cp "/tmp/diskid_check_${pool}.txt" "${MOUNTPOINT}/tmp/"
      cp "/tmp/update_crypttab_${pool}.sh" "${MOUNTPOINT}/tmp/"
      chroot "${MOUNTPOINT}" /bin/bash -x "/tmp/update_crypttab_${pool}.sh"
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
# description
# Globals:
#   debian_priority
#   EFI_BOOT_SIZE
#   INSTALL_WARNING_LEVEL
#   TOPOLOGY_ROOT
#   ZFS_ROOT_ENCRYPT
#   ZFS_ROOT_PASSWORD
#   diskid
#   swap_size
# Arguments:
#  None
#######################################
function prepare_install_environment() {
  export debian_priority="${INSTALL_WARNING_LEVEL#*=}"

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

  case "${TOPOLOGY_ROOT}" in
    single|mirror)
      swap_hex_code="8200"
      ;;
    raid0|raidz*)
      swap_hex_code="FD00"
      ;;
  esac

  if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
    case "${ZFS_ROOT_ENCRYPT}" in
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
    sgdisk -n1:1M:+"${EFI_BOOT_SIZE}"M -t1:EF00 "/dev/disk/by-id/${diskid}"
    sgdisk -n2:0:+"${swap_size}"M -t2:"${swap_hex_code}" "/dev/disk/by-id/${diskid}"
    sgdisk -n3:0:0 -t3:"${root_hex_code}" "/dev/disk/by-id/${diskid}"
  done < "/tmp/diskid_check_root.txt"

  partprobe
  sleep 2
}

#######################################
# description
# Globals:
#   MOUNTPOINT
#   rootzfs_full_name
#   RPOOL
# Arguments:
#  None
#######################################
function create_zfs_pools() {
  create_zpool "root"

  partprobe
  sleep 2

  # Create filesystem datasets
  zfs create -o canmount=off -o mountpoint=none "${RPOOL}/ROOT"

  rootzfs_full_name="ubuntu.$(date +%Y.%m.%d)"
  zfs create -o canmount=noauto -o mountpoint=/ "${RPOOL}/ROOT/${rootzfs_full_name}"
  zfs mount "${RPOOL}/ROOT/${rootzfs_full_name}"
  zpool set bootfs="${RPOOL}/ROOT/${rootzfs_full_name}" "${RPOOL}"

  # Create system datasets
  zfs create "${RPOOL}/srv"
  zfs create -o canmount=off "${RPOOL}/usr"
  zfs create "${RPOOL}/usr/local"
  zfs create -o canmount=off "${RPOOL}/var"
  zfs create -o canmount=off "${RPOOL}/var/lib"
  zfs create "${RPOOL}/var/games"
  zfs create "${RPOOL}/var/log"
  zfs create "${RPOOL}/var/mail"
  zfs create "${RPOOL}/var/snap"
  zfs create "${RPOOL}/var/spool"
  zfs create "${RPOOL}/var/www"

  # User data datasets
  zfs create "${RPOOL}/home"
  zfs create -o mountpoint=/root "${RPOOL}/home/root"
  chmod 700 "${MOUNTPOINT}/root"

  # Exclude from snapshots
  zfs create -o com.sun:auto-snapshot=false "${RPOOL}/var/cache"
  zfs create -o com.sun:auto-snapshot=false "${RPOOL}/var/tmp"
  chmod 1777 "${MOUNTPOINT}/var/tmp"
  zfs create -o com.sun:auto-snapshot=false "${RPOOL}/var/lib/docker"

  # Mount tmpfs at /run
  mkdir -p "${MOUNTPOINT}/run"
  mount -t tmpfs tmpfs "${MOUNTPOINT}/run"
}

#######################################
# description
# Globals:
#   MOUNTPOINT
#   squashfs_path
#   squashfs_type
# Arguments:
#  None
#######################################
function extract_live_filesystem() {
  local free_space
  free_space="$(df -k --output=avail "${MOUNTPOINT}" | tail -n1)"

  if [[ "${free_space}" -lt 5242880 ]]; then
    echo "Less than 5 GBs free!"
    exit 1
  fi

  echo "Extracting live filesystem to ${MOUNTPOINT}..."

  case "${squashfs_type}" in
    mounted)
      # Copy from already-mounted filesystem
      echo "Copying from mounted filesystem at ${squashfs_path}..."
      rsync -aHAXS --info=progress2 "${squashfs_path}/" "${MOUNTPOINT}/"
      ;;
    squashfs)
      # Extract squashfs file
      if ! command -v unsquashfs &>/dev/null; then
        echo "Installing squashfs-tools..."
        apt-get install -y squashfs-tools
      fi

      echo "Extracting squashfs from ${squashfs_path}..."
      unsquashfs -f -d "${MOUNTPOINT}" "${squashfs_path}"
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
  rm -f "${MOUNTPOINT}/etc/casper.conf"
  rm -rf "${MOUNTPOINT}/etc/live"
  rm -f "${MOUNTPOINT}/etc/fstab"

  # Create fresh fstab
  cat > "${MOUNTPOINT}/etc/fstab" <<-EOF
		# /etc/fstab: static file system information.
		# <file system> <mount point> <type> <options> <dump> <pass>
	EOF

  # Remove live user if exists
  if [[ -d "${MOUNTPOINT}/home/kubuntu" ]]; then
    rm -rf "${MOUNTPOINT}/home/kubuntu"
  fi
  if [[ -d "${MOUNTPOINT}/home/ubuntu" ]]; then
    rm -rf "${MOUNTPOINT}/home/ubuntu"
  fi

  # Remove live-specific packages list
  rm -f "${MOUNTPOINT}/etc/apt/sources.list.d/cdrom.list"

  # Remove installer artifacts
  rm -rf "${MOUNTPOINT}/var/log/installer"
  rm -f "${MOUNTPOINT}/var/lib/dpkg/status-old"

  # Clean apt cache from live system
  rm -rf "${MOUNTPOINT}/var/cache/apt/archives"/*.deb
  rm -rf "${MOUNTPOINT}/var/lib/apt/lists"/*

  echo "Cleanup complete."
}



#######################################
# description
# Globals:
#   ETH_PREFIX
#   HOSTNAME
#   INSTALL_WARNING_LEVEL
#   LOCALE
#   MOUNTPOINT
#   TIMEZONE
# Arguments:
#  None
#######################################
function system_setup_part1() {
  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		export DEBIAN_PRIORITY="${INSTALL_WARNING_LEVEL#*=}"
	EOCHROOT

  echo "${HOSTNAME}" > "${MOUNTPOINT}/etc/hostname"
  echo "127.0.1.1       ${HOSTNAME}" >> "${MOUNTPOINT}/etc/hosts"

  local eth_interface
  eth_interface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ETH_PREFIX}*" | head -1)")"

  # Create netplan config directory if needed
  mkdir -p "${MOUNTPOINT}/etc/netplan"

  cat > "${MOUNTPOINT}/etc/netplan/01-${eth_interface}.yaml" <<-EOF
		network:
		  version: 2
		  ethernets:
		    ${eth_interface}:
		      dhcp4: yes
	EOF
  chmod 600 "${MOUNTPOINT}/etc/netplan/01-${eth_interface}.yaml"

  mount --rbind /dev "${MOUNTPOINT}/dev"
  mount --rbind /proc "${MOUNTPOINT}/proc"
  mount --rbind /sys "${MOUNTPOINT}/sys"

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		locale-gen en_US.UTF-8 ${LOCALE}
		echo 'LANG="${LOCALE}"' > /etc/default/locale

		ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime
		dpkg-reconfigure -f noninteractive tzdata
	EOCHROOT
}

#######################################
# description
# Globals:
#   MOUNTPOINT
# Arguments:
#  None
#######################################
function system_setup_part2() {
  # Most packages should already be present from the live filesystem
  # Just ensure ZFS tools are properly configured
  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
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
# description
# Globals:
#   INITIAL_BOOT_ORDER
#   MOUNTPOINT
#   TIMEOUT_REFIND
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
      echo "${esp_mount}" >> "${MOUNTPOINT}/tmp/backup_esp_mounts.txt"
    fi

    echo "Creating FAT32 filesystem on ${diskid}. ESP: ${esp_mount}"
    umount -q "/dev/disk/by-id/${diskid}-part1" || true
    mkdosfs -F 32 -s 1 -n EFI "/dev/disk/by-id/${diskid}-part1"
    partprobe
    sleep 2

    local blkid_part1
    blkid_part1="$(blkid -s UUID -o value "/dev/disk/by-id/${diskid}-part1")"
    echo "${blkid_part1}" >> /tmp/esp_partition_list_uuid.txt

    chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
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

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		apt-get -yq install refind kexec-tools
		apt-get install --yes dpkg-dev git systemd-sysv

		sed -i 's,^timeout .*,timeout ${TIMEOUT_REFIND},' /boot/efi/EFI/refind/refind.conf

		echo REMAKE_INITRD=yes > /etc/dkms/zfs.conf
		sed -i 's,LOAD_KEXEC=false,LOAD_KEXEC=true,' /etc/default/kexec
	EOCHROOT

  INITIAL_BOOT_ORDER="${initial_boot_order}"
}

#######################################
# description
# Globals:
#   MOUNTPOINT
#   QUIET_BOOT
#   REMOTEACCESS_FIRST_BOOT
#   RPOOL
#   TIMEOUT_ZBM_NO_REMOTE
#   ZFS_ROOT_ENCRYPT
#   ZFS_ROOT_PASSWORD
# Arguments:
#  None
#######################################
function system_setup_part4() {
  cp "/tmp/diskid_check_root.txt" "${MOUNTPOINT}/tmp/"

  if [[ -f "/tmp/luks_dmname_root.txt" ]]; then
    cp "/tmp/luks_dmname_root.txt" "${MOUNTPOINT}/tmp/"
  fi

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
		  case "${ZFS_ROOT_ENCRYPT}" in
		    native)
		      echo "${ZFS_ROOT_PASSWORD}" > /etc/zfs/${RPOOL}.key
		      chmod 600 /etc/zfs/${RPOOL}.key
		      zfs change-key -o keylocation=file:///etc/zfs/${RPOOL}.key \
		        -o keyformat=passphrase ${RPOOL}
		      zfs set org.zfsbootmenu:keysource="${RPOOL}/ROOT" ${RPOOL}
		      ;;
		    luks)
		      mkdir -p /etc/cryptsetup-keys.d/
		      dd if=/dev/urandom of=/etc/cryptsetup-keys.d/${RPOOL}.key bs=1024 count=4
		      chmod 600 /etc/cryptsetup-keys.d/${RPOOL}.key
		      ;;
		  esac
		fi

		echo "UMASK=0077" > /etc/initramfs-tools/conf.d/umask.conf
	EOCHROOT

  if [[ "${ZFS_ROOT_ENCRYPT}" == "luks" ]]; then
    update_crypttab "chroot" "root"
  fi

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		if [[ "${QUIET_BOOT}" == "yes" ]]; then
		  zfs set org.zfsbootmenu:commandline="spl_hostid=\$(hostid) ro quiet" "${RPOOL}/ROOT"
		else
		  zfs set org.zfsbootmenu:commandline="spl_hostid=\$(hostid) ro" "${RPOOL}/ROOT"
		fi
	EOCHROOT

  zfsbootmenu_install_config "chroot"

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		cat > /boot/efi/EFI/ubuntu/refind_linux.conf <<-EOF
			"Boot default"  "zbm.timeout=${TIMEOUT_ZBM_NO_REMOTE} ro quiet loglevel=0"
			"Boot to menu"  "zbm.show ro quiet loglevel=0"
		EOF

		if [[ "${QUIET_BOOT}" == "no" ]]; then
		  sed -i 's,ro quiet,ro,' /boot/efi/EFI/ubuntu/refind_linux.conf
		fi
	EOCHROOT

  # Handle multiple ESPs
  local topology
  topology="$(cat /tmp/topology_pool_pointer.txt)"

  if [[ "${topology}" != "single" ]]; then
    zbm_multiple_esp
  fi

  if [[ "${REMOTEACCESS_FIRST_BOOT}" == "yes" ]]; then
    remote_zbm_access "chroot"
  fi
}

#######################################
# description
# Globals:
#   DISKS_ROOT
#   MOUNTPOINT
#   PASSWORD
#   TOPOLOGY_ROOT
#   ZFS_ROOT_PASSWORD
# Arguments:
#  None
#######################################
function system_setup_part5() {
  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		echo "root:${PASSWORD}" | chpasswd -c SHA256
	EOCHROOT

  # Configure swap
  local crypttab_params="/dev/urandom plain,swap,cipher=aes-xts-plain64:sha256,size=512"

  case "${TOPOLOGY_ROOT}" in
    single)
      local diskid
      diskid="$(cat /tmp/diskid_check_root.txt)"
      if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
        chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
					apt-get install --yes cryptsetup
					echo "swap /dev/disk/by-id/${diskid}-part2 ${crypttab_params}" >> /etc/crypttab
					echo "/dev/mapper/swap none swap defaults 0 0" >> /etc/fstab
				EOCHROOT
      else
        chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
					mkswap -f "/dev/disk/by-id/${diskid}-part2"
					blkid_part2="\$(blkid -s UUID -o value /dev/disk/by-id/${diskid}-part2)"
					echo "/dev/disk/by-uuid/\${blkid_part2} none swap defaults 0 0" >> /etc/fstab
					sleep 2
					swapon -a
				EOCHROOT
      fi
      ;;
    mirror)
      mdadm_swap "mirror" "${DISKS_ROOT}"
      ;;
    raid0)
      configure_raid0_swap
      ;;
    raidz1)
      mdadm_swap "5" "${DISKS_ROOT}"
      ;;
    raidz2|raidz3)
      mdadm_swap "6" "${DISKS_ROOT}"
      ;;
  esac

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
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

    if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
      echo "${swap_name} /dev/disk/by-id/${diskid}-part2 ${crypttab_params}" >> "${MOUNTPOINT}/etc/crypttab"
      echo "/dev/mapper/${swap_name} none swap defaults,pri=1 0 0" >> "${MOUNTPOINT}/etc/fstab"
    else
      mkswap -f "/dev/disk/by-id/${diskid}-part2"
      local blkid_part2
      blkid_part2="$(blkid -s UUID -o value "/dev/disk/by-id/${diskid}-part2")"
      echo "/dev/disk/by-uuid/${blkid_part2} none swap defaults,pri=1 0 0" >> "${MOUNTPOINT}/etc/fstab"
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

  if [[ -n "${ZFS_ROOT_PASSWORD}" ]]; then
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

  cp "${mdadm_swap_loc}" "${MOUNTPOINT}/tmp/"
  chroot "${MOUNTPOINT}" /bin/bash -x "${mdadm_swap_loc}"
}



#######################################
# description
# Globals:
#   MOUNTPOINT
#   QUIET_BOOT
#   ZFS_ROOT_ENCRYPT
#   ZFS_ROOT_PASSWORD
# Arguments:
#   1
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
  if [[ "${QUIET_BOOT}" == "no" ]]; then
    cat >> "${zfsbootmenu_script}" <<-'EOF'

			sed -i 's,ro quiet,ro,' /etc/zfsbootmenu/config.yaml
		EOF
  fi

  # Add LUKS hook if needed
  if [[ -n "${ZFS_ROOT_PASSWORD}" && "${ZFS_ROOT_ENCRYPT}" == "luks" ]]; then
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
      cp "${zfsbootmenu_script}" "${MOUNTPOINT}/tmp/"
      chroot "${MOUNTPOINT}" /bin/bash -x "${zfsbootmenu_script}"
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

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
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
  revised_order="${revised_order},${INITIAL_BOOT_ORDER}"

  efibootmgr -o "${revised_order}"
}

# Remote access to ZFSBootMenu via SSH
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

		case "${REMOTEACCESS_IP_CONFIG}" in
		  dhcp|dhcp,dhcp6|dhcp6)
		    echo "ip=${REMOTEACCESS_IP_CONFIG} rd.neednet=1" > /etc/cmdline.d/dracut-network.conf
		    ;;
		  static)
		    echo "ip=${REMOTEACCESS_IP}:::${REMOTEACCESS_NETMASK}:::none rd.neednet=1 rd.break" > /etc/cmdline.d/dracut-network.conf
		    ;;
		esac

		echo 'send fqdn.fqdn "${REMOTEACCESS_HOSTNAME}";' >> /usr/lib/dracut/modules.d/35network-legacy/dhclient.conf

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
			#dropbear_acl="/home/${NEW_USER}/.ssh/authorized_keys"
		EOF

		systemctl stop dropbear || true
		systemctl disable dropbear || true

		sed -i 's,zbm.timeout=${TIMEOUT_ZBM_NO_REMOTE},zbm.timeout=${TIMEOUT_ZBM_REMOTE},' /boot/efi/EFI/ubuntu/refind_linux.conf

		generate-zbm --debug
	EOSCRIPT

  case "${script_env}" in
    chroot)
      cp /tmp/remote_zbm_access.sh "${MOUNTPOINT}/tmp/"
      chroot "${MOUNTPOINT}" /bin/bash -x /tmp/remote_zbm_access.sh
      ;;
    base)
      if grep -q casper /proc/cmdline; then
        echo "Live environment present. Reboot into new installation."
        exit 1
      fi

      /bin/bash /tmp/remote_zbm_access.sh

      sed -i 's,#dropbear_acl,dropbear_acl,' /etc/zfsbootmenu/dracut.conf.d/dropbear.conf
      mkdir -p "/home/${NEW_USER}/.ssh"
      chown "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}/.ssh"
      touch "/home/${NEW_USER}/.ssh/authorized_keys"
      chmod 644 "/home/${NEW_USER}/.ssh/authorized_keys"
      chown "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}/.ssh/authorized_keys"

      echo "ZFSBootMenu remote access installed."
      echo "Connect as root on port 222: ssh root@{IP} -p 222"
      echo "Add your SSH public key to /home/${NEW_USER}/.ssh/authorized_keys"
      echo "Then run: sudo generate-zbm"
      ;;
    *)
      exit 1
      ;;
  esac
}



#######################################
# description
# Globals:
#   MOUNTPOINT
#   NEW_USER
#   PASSWORD
#   RPOOL
# Arguments:
#  None
#######################################
function user_setup() {
  zfs create -o mountpoint="/home/${NEW_USER}" "${RPOOL}/home/${NEW_USER}"
  zfs create -o compression=off "${RPOOL}/home/${NEW_USER}/Videos"
  zfs create -o compression=off "${RPOOL}/home/${NEW_USER}/Downloads"
  zfs create -o compression=off "${RPOOL}/home/${NEW_USER}/Music"

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		adduser --disabled-password --gecos "" "${NEW_USER}"
		cp -a /etc/skel/. "/home/${NEW_USER}"
		chown -R "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}"
		usermod -a -G adm,cdrom,dip,lpadmin,lxd,plugdev,sambashare,sudo "${NEW_USER}"
		echo "${NEW_USER}:${PASSWORD}" | chpasswd

		cat > /etc/sudoers.d/99-nopasswd-apt <<-EOSUDOERS
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/apt
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/apt-get
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/apt-cache
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/dpkg
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/snap
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/flatpak
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/bin/plasma-discover
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/lib/x86_64-linux-gnu/libexec/discover/DiscoverNotifier
			${NEW_USER} ALL=(ALL) NOPASSWD: /usr/libexec/packagekitd
		EOSUDOERS
		chmod 440 /etc/sudoers.d/99-nopasswd-apt
	EOCHROOT
}

#######################################
# description
# Globals:
#   debian_priority
#   DISTRO_VARIANT
#   INSTALL_WARNING_LEVEL
#   MIRROR_ARCHIVE
#   RPOOL
# Arguments:
#  None
#######################################
function distro_install() {
  # Desktop already installed from squashfs, just update and ensure packages
  export debian_priority="${INSTALL_WARNING_LEVEL#*=}"

  if [[ -n "${MIRROR_ARCHIVE}" ]]; then
    apt_mirror_source
  fi

  apt-get update
  apt-get dist-upgrade --yes

  # Create AccountsService dataset for desktop variants
  if [[ "${DISTRO_VARIANT}" != "server" ]]; then
    if ! zfs list "${RPOOL}/var/lib/AccountsService" &>/dev/null; then
      zfs create "${RPOOL}/var/lib/AccountsService"
    fi
  fi

  # Ensure the correct display manager is set
  case "${DISTRO_VARIANT}" in
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
# description
# Globals:
#   ETH_PREFIX
# Arguments:
#  None
# Returns:
#   0 ...
#######################################
function network_manager_config() {
  if ! dpkg-query --show --showformat='${db:Status-Status}\n' "network-manager" 2>/dev/null | grep -q "installed"; then
    return 0
  fi

  local eth_interface
  eth_interface="$(basename "$(find /sys/class/net -maxdepth 1 -mindepth 1 -name "${ETH_PREFIX}*" | head -1)")"

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
# description
# Globals:
#   RPOOL
# Arguments:
#  None
#######################################
function sanoid_install() {
  apt-get update
  apt-get install -y sanoid

  mkdir -p /etc/sanoid

  cat > /etc/sanoid/sanoid.conf <<-EOF
		[${RPOOL}/ROOT]
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
		DPkg::Pre-Invoke { "echo 'Creating ZFS snapshot.'; ts=${pre_apt_prefix}_\$(date +%F_%H:%M:%S); zfs snapshot -r ${RPOOL}/ROOT@\${ts} && zfs destroy ${RPOOL}/ROOT@\${ts} || true"; };
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
# description
# Globals:
#   EXTRA_PROGRAMS
# Arguments:
#  None
# Returns:
#   0 ...
#######################################
function extra_programs_install() {
  if [[ "${EXTRA_PROGRAMS}" != "yes" ]]; then
    return 0
  fi

  apt-get install -yq cifs-utils
  apt-get install -y openssh-server
  apt-get install --yes man-db tldr locate
}

#######################################
# description
# Globals:
#   MOUNTPOINT
# Arguments:
#  None
#######################################
function log_compress_disable() {
  chroot "${MOUNTPOINT}" /bin/bash -x <<-'EOCHROOT'
		for file in /etc/logrotate.d/*; do
		  if grep -Eq "(^|[^#y])compress" "${file}"; then
		    sed -i -r "s/(^|[^#y])(compress)/\1#\2/" "${file}"
		  fi
		done
	EOCHROOT
}

#######################################
# description
# Globals:
#   kb_console_settings
#   MOUNTPOINT
# Arguments:
#  None
#######################################
function keyboard_console_setup() {
  cp "${kb_console_settings}" "${MOUNTPOINT}/tmp/"

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		apt-get install -y debconf-utils
		debconf-set-selections < "/tmp/$(basename "${kb_console_settings}")"
		rm -f /etc/default/keyboard
		dpkg-reconfigure -f noninteractive keyboard-configuration
		dpkg-reconfigure -f noninteractive console-setup
	EOCHROOT
}

#######################################
# description
# Globals:
#   MOUNTPOINT
#   rootzfs_full_name
#   RPOOL
# Arguments:
#  None
#######################################
function fix_fs_mount_order() {
  identify_ubuntu_dataset_uuid

  chroot "${MOUNTPOINT}" /bin/bash -x <<-EOCHROOT
		mkdir -p /etc/zfs/zfs-list.cache
		touch "/etc/zfs/zfs-list.cache/${RPOOL}"

		zed -F &
		sleep 2

		while [[ ! -s "/etc/zfs/zfs-list.cache/${RPOOL}" ]]; do
		  zfs set canmount=noauto "${RPOOL}/ROOT/${rootzfs_full_name}"
		  sleep 1
		done

		pkill -9 "zed" || true
		sleep 2

		sed -Ei "s|${MOUNTPOINT}/?|/|" "/etc/zfs/zfs-list.cache/${RPOOL}"
	EOCHROOT
}

#######################################
# description
# Globals:
#   MOUNTPOINT
# Arguments:
#  None
#######################################
function unmount_datasets() {
  mount --make-rslave "${MOUNTPOINT}/dev"
  mount --make-rslave "${MOUNTPOINT}/proc"
  mount --make-rslave "${MOUNTPOINT}/sys"

  grep "${MOUNTPOINT}" /proc/mounts | cut -f2 -d" " | sort -r | xargs -r umount -n
}



#######################################
# description
# Globals:
#   DATAPOOL
#   DATAPOOL_MOUNT
#   NEW_USER
#   RPOOL
#   ZFS_DATA_ENCRYPT
#   ZFS_DATA_PASSWORD
#   _
# Arguments:
#  None
#######################################
function create_data_pool() {
  disclaimer

  if zpool status "${DATAPOOL}" &>/dev/null; then
    echo "Warning: ${DATAPOOL} already exists. Continue to destroy it?"
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
  fi

  if [[ -n "${ZFS_DATA_PASSWORD}" ]]; then
    echo "Warning: Data pool will use root pool keyfile for auto-unlock."
    echo "Press Enter to Continue or CTRL+C to abort."
    read -r _
  fi

  get_disk_id_pool "data"
  clear_partition_table "data"
  partprobe
  sleep 2

  if [[ ! -d "${DATAPOOL_MOUNT}" ]]; then
    mkdir -p "${DATAPOOL_MOUNT}"
    chown "${NEW_USER}:${NEW_USER}" "${DATAPOOL_MOUNT}"
  fi

  touch "/etc/zfs/zfs-list.cache/${DATAPOOL}"

  create_zpool "data"

  if [[ "${ZFS_DATA_ENCRYPT}" == "luks" ]]; then
    if [[ -f "/etc/cryptsetup-keys.d/${RPOOL}.key" ]]; then
      update_crypttab "base" "data"
    else
      echo "${RPOOL}.key not found."
      exit 1
    fi
  fi

  while [[ ! -s "/etc/zfs/zfs-list.cache/${DATAPOOL}" ]]; do
    zfs set canmount=on "${DATAPOOL}"
    sleep 1
  done

  ln -s "${DATAPOOL_MOUNT}" "/home/${NEW_USER}/"
  chown -R "${NEW_USER}:${NEW_USER}" "${DATAPOOL_MOUNT}" "/home/${NEW_USER}/${DATAPOOL}"

  zpool status
  zfs list
}



#######################################
# description
# Globals:
#   choice
# Arguments:
#  None
#######################################
function reinstall_zbm() {
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
# description
# Globals:
#   NEW_USER
#   PASSWORD
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
  echo "First login: ${NEW_USER}:${PASSWORD}"
  echo "After reboot, run script with 'postreboot' option."
}

#######################################
# description
# Globals:
#   DISTRO_VARIANT
#   _
# Arguments:
#  None
#######################################
function post_reboot() {
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

  echo "Installation complete: ${DISTRO_VARIANT}."
  echo "Reboot recommended."
}

#######################################
# description
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
# description
# Globals:
#   DATAPOOL
#   DATAPOOL_MOUNT
#   DISKS_DATA
#   DISKS_ROOT
#   DISTRO_VARIANT
#   EFI_BOOT_SIZE
#   ETH_PREFIX
#   EXTRA_PROGRAMS
#   HOSTNAME
#   INSTALL_LOG
#   INSTALL_WARNING_LEVEL
#   LOCALE
#   LOG_LOC
#   MIRROR_ARCHIVE
#   MOUNTPOINT
#   NEW_USER
#   PASSWORD
#   QUIET_BOOT
#   REMOTEACCESS_FIRST_BOOT
#   REMOTEACCESS_HOSTNAME
#   REMOTEACCESS_IP
#   REMOTEACCESS_IP_CONFIG
#   REMOTEACCESS_NETMASK
#   RPOOL
#   TIMEOUT_REFIND
#   TIMEOUT_ZBM_NO_REMOTE
#   TIMEOUT_ZBM_REMOTE
#   TIMEZONE
#   TOPOLOGY_DATA
#   TOPOLOGY_ROOT
#   UBUNTU_ORIGINAL
#   UBUNTU_VER
#   ZFS_COMPRESSION
#   ZFS_DATA_ENCRYPT
#   ZFS_DATA_PASSWORD
#   ZFS_DPOOL_ASHIFT
#   ZFS_ROOT_ENCRYPT
#   ZFS_ROOT_PASSWORD
#   ZFS_RPOOL_ASHIFT
#   _
#   swap_size
#   total_ram_mb
# Arguments:
#   0
#   1
#######################################
function main() {
# shellcheck disable=SC2317  # Don't warn about unreachable commands


set -euo pipefail


#######################################
# Configuration Variables
#######################################


# Ubuntu release and variant
readonly UBUNTU_VER="questing"
# jammy (22.04), noble (24.04), questing (25.10)
readonly DISTRO_VARIANT="kubuntu"
# server, desktop, kubuntu, xubuntu, budgie, MATE


# User account
readonly NEW_USER="me"
readonly PASSWORD="Willy123$"
readonly HOSTNAME="precision"


# ZFS root pool encryption
readonly ZFS_ROOT_PASSWORD=""
# Minimum 8 chars, empty for no encryption
readonly ZFS_ROOT_ENCRYPT="native"
# native or luks


# Locale and timezone
readonly LOCALE="en_US.UTF-8"
readonly TIMEZONE="America/New_York"


# ZFS pool settings
readonly ZFS_RPOOL_ASHIFT="12"
# 9=512B, 12=4KiB, 13=8KiB sectors
readonly ZFS_COMPRESSION="zstd"
# lz4 or zstd
readonly MIRROR_ARCHIVE=""
# ISO 3166-1 alpha-2 country code or empty


# Root pool configuration
readonly RPOOL="rpool"
readonly TOPOLOGY_ROOT="raidz1"
# single, mirror, raid0, raidz1, raidz2, raidz3
readonly DISKS_ROOT="3"
# Number of disks (ignored for single)
readonly EFI_BOOT_SIZE="512"
# EFI partition size in MiB
swap_size=""
# Empty for auto-calculate based on RAM


# Data pool configuration
readonly DATAPOOL="datapool"
readonly TOPOLOGY_DATA="single"
# single, mirror, raid0, raidz1, raidz2, raidz3
# shellcheck disable=SC2034  # Used via indirect reference
readonly DISKS_DATA="1"
# Number of disks (ignored for single)
readonly ZFS_DATA_PASSWORD=""
# Only used if root pool has no password
readonly ZFS_DATA_ENCRYPT="native"
# native or luks
readonly DATAPOOL_MOUNT="/mnt/${DATAPOOL}"
readonly ZFS_DPOOL_ASHIFT="12"


# Installation paths
readonly MOUNTPOINT="/mnt/ub_server"
readonly INSTALL_LOG="ubuntu_setup_zfs_root.log"
readonly LOG_LOC="/var/log"


# Boot and remote access settings
readonly REMOTEACCESS_FIRST_BOOT="no"
readonly TIMEOUT_REFIND="3"
readonly TIMEOUT_ZBM_NO_REMOTE="3"
readonly TIMEOUT_ZBM_REMOTE="45"
readonly QUIET_BOOT="yes"


# Network settings
readonly ETH_PREFIX="e"
readonly REMOTEACCESS_HOSTNAME="zbm"
readonly REMOTEACCESS_IP_CONFIG="dhcp"
# dhcp, dhcp,dhcp6, dhcp6, or static
readonly REMOTEACCESS_IP="192.168.0.222"
readonly REMOTEACCESS_NETMASK="255.255.255.0"


# Package sources
readonly UBUNTU_ORIGINAL="http://atl.mirrors.clouvider.net/ubuntu/"
readonly INSTALL_WARNING_LEVEL="PRIORITY=critical"
# or FRONTEND=noninteractive
readonly EXTRA_PROGRAMS="yes"


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


# Check encryption method is defined if password is set
if [[ -n "${ZFS_ROOT_PASSWORD}" && -z "${ZFS_ROOT_ENCRYPT}" ]]; then
  echo "Password entered but no encryption method defined."
  exit 1
fi


# Auto-calculate swap size based on system RAM if not set
if [[ -z "${swap_size}" ]]; then
  total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')

  case "${TOPOLOGY_ROOT}" in
    single|mirror)
      swap_size="${total_ram_mb}"
      ;;
    raid0)
      swap_size=$((total_ram_mb / DISKS_ROOT))
      ;;
    raidz1)
      swap_size=$((total_ram_mb / (DISKS_ROOT - 1)))
      ;;
    raidz2)
      swap_size=$((total_ram_mb / (DISKS_ROOT - 2)))
      ;;
    raidz3)
      swap_size=$((total_ram_mb / (DISKS_ROOT - 3)))
      ;;
  esac

  echo "Auto-calculated swap_size: ${swap_size} MiB per disk"
fi


#######################################
# Utility Functions
#######################################


#######################################
# ZFS Pool Functions
#######################################


#######################################
# Debootstrap Functions
#######################################


#######################################
# System Setup Functions
#######################################


#######################################
# ZFSBootMenu Functions
#######################################


#######################################
# User and Post-Install Functions
#######################################


#######################################
# Data Pool Functions
#######################################


#######################################
# Reinstall Functions
#######################################


#######################################
# Main Entry Points
#######################################


#######################################
# Script Execution
#######################################


log_func
date


# Update system time
timedatectl || true
if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
  systemctl restart systemd-timesyncd.service || true
elif systemctl is-active --quiet chrony 2>/dev/null; then
  chronyc burst 4/4 || true
  chronyc makestep || true
fi
timedatectl || true


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