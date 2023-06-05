#!/bin/bash
#
# Skip's "universal" lookaside grabber
# Updated by Peter Ajamian
#
# Run this in a Fedora/Rocky/CentOS/CentOS Stream source directory, and it will retrieve the lookaside sources (tarballs) into the current directory
#

shopt -s nullglob extglob

# List of lookaside locations and their patterns
# This can be easily edited to add more distro locations, or change their order for less 404 misses:
lookasides=(
https://rocky-linux-sources-staging.a1.rockylinux.org/%HASH%
https://sources.build.resf.org/%HASH%
https://git.centos.org/sources/%PKG%/%BRANCH%/%HASH%
https://sources.stream.centos.org/sources/rpms/%PKG%/%FILENAME%/%SHATYPE%/%HASH%/%FILENAME%
https://src.fedoraproject.org/repo/pkgs/%PKG%/%FILENAME%/%SHATYPE%/%HASH%/%FILENAME%
)

# These are glob patterns.  They should be in the same order as the lookasides
# above and need to be quoted to avoid early glob expansion.
remotes=(
    '@(git@|http?(s)://)git.rockylinux.org*'
    '@(git@|http?(s)://)git.rockylinux.org*'
    '@(ssh://git@|http?(s)://)git.centos.org/*'
    '@(ssh://git@|http?(s)://)gitlab.com[:/]redhat/centos-stream/*'
    '@(ssh://git@|http?(s)://)src.fedoraproject.org/*'
)

# These are branch names that will be glob-matched to to the lookasides above.
# Missing entries or empty strings will default to matching any branch.
branches=(
    r8
    r9
    ''
    ''
    ''
)

declare -A macros

#
# Get the hash type for a given hash.  Based on the length of the hash.
#
shasizes=(
    [32]=md5
    [40]=sha1
    [64]=sha256
    [96]=sha384
    [128]=sha512
)
hashtype () {
    printf '%s' "${shasizes[${#1}]}"
}

#
# Validate a file against the passed hash.
# Synopsis: check_file filename hash [hashtype]
#
check_file () {
    [[ -r $1 ]] || return
    local type
    if (( $# >= 3 )); then
	type=$3
    else
	type=$(hashtype "$2")
    fi

    # We use one of the "sum" commands, so the command name is the type followed
    # by "sum".
    "${type}sum" --status -c - <<<"$2  $1"
}

###
# Function that actually downloads a lookaside source
# Takes HASH / FILENAME / BRANCH / PKG / SHATYPE as arguments $1 / $2 / $3 / $4 / $5
function download {
    # If the file already exists and matches the checksum then we don't need to
    # download it again.
    if check_file "${macros[FILENAME]}" "${macros[HASH]}" "${macros[SHATYPE]}"
    then
	printf 'File %s already exists and matches the passed hash ... %s\n' \
	    "${macros[FILENAME]}" 'skipping.'
	return
    fi

    # We need to re-order the lookasides according to the remote and branch
    # macro entries.
    local -a urls
    local -A tried

    # Start by looking for matching entries
    if [[ ${macros[REMOTE]} ]]; then
	shopt -s nocasematch
	for ((i=0; i<${#lookasides[@]}; i++)); do
	    # shellcheck disable=SC2053
	    [[ ${macros[REMOTE]} == ${remotes[i]} ]] || continue
	    # shellcheck disable=SC2053
	    [[ ${macros[BRANCH]} == ${branches[i]:=\*} ]] || continue

	    urls+=("${lookasides[i]}")
	    tried[${lookasides[i]}]=1
	done
	shopt -u nocasematch
    fi

    # Then pile the rest of the URLs onto the end.
    for url in "${lookasides[@]}"; do
	[[ ${tried[$url]} ]] && continue
	urls+=("$url")
	tried[$url]=1
    done

    for url in "${urls[@]}"; do
	# Substitute each of our macros (%PKG%, %HASH%, etc.):
	for k in "${!macros[@]}"; do
	    v=${macros[$k]}
	    url=${url//"%$k%"/$v}
	done

	# Download the file with curl, return if successful.
	printf 'Trying: %s\n' "$url"
	curl --create-dirs -sfLRo "${macros[FILENAME]}" "$url" || continue
	check_file "${macros[FILENAME]}" "${macros[HASH]}" \
	    "${macros[SHATYPE]}" || {
	    printf 'Invalid or corrupted file downloaded.  Trying next URL.\n'
	    continue
	}
	
	printf 'Downloaded: %s  ----->  %s\n' "$url" "${macros[FILENAME]}"
	return
    done

    echo "ERROR: Unable to find lookaside file with the following HASH / FILENAME / BRANCH / PKG / SHATYPE :"
    echo "${macros[HASH]}  /  ${macros[FILENAME]}  /  ${macros[BRANCH]}  /  ${macros[PKG]}  /  ${macros[SHATYPE]}"
    exit 1
}




###
# discover our list of lookaside sources.  They are either in a "sources" file (new), or the older ".packagename.metadata" format (old)
sourcesfiles=(.*.metadata sources)
mapfile -t sourcelines < <(cat "${sourcesfiles[@]}" 2>/dev/null)

if (( ${#sourcelines[@]} == 0 )); then
  echo "ERROR: Cannot find .*.metadata or sources file listing sources.  Are you in the right directory?"
  exit 1
fi


# Current git branch.  We don't error out if this fails, as we may not necessarily need this info
macros[BRANCH]=$(git status | sed -n 's/.*On branch //p')



# Source package name should match the specfile - we'll use that in lieu of parsing "Name:" out of it
# There could def. be a better way to do this....
# UPDATE: The better way is to use rpmspec, but this may not be installed, so
# fall back to the old way if it isn't.
specfile=(*.spec SPECS/*.spec)
if (( ${#specfile[@]}!= 1 )); then
    echo "ERROR: Exactly one spec file expected, ${#specfile[@]} found."
    exit 1
fi

macros[PKG]=$(rpmspec -q --qf '%{NAME}\n' --srpm "${specfile[0]}" 2>/dev/null) || {
    pkg=${specfile[0]##*/}
    macros[PKG]=${pkg%.spec}
}

if (( ${#macros[PKG]} < 2 )); then
  echo "ERROR: Having trouble finding the name of the package based on the name of the .spec file."
  exit 1
fi

# Get the remote origin from git if we can.  This is not required but it will
# help us to determine which lookaside URL to try first.
# We look for a fetch remote tagged with origin, otherwise we get the first
# fetch remote that is returned.
macros[REMOTE]=""
while read -r name url direction; do
    # Make sure the direction is fetch.
    [[ $direction == '(fetch)' ]] || continue

    # If the name is "origin" we need to use this url.
    if [[ $name == 'origin' ]]; then
	macros[REMOTE]=$url
	break
    fi

    # Otherwise we set the first url we encounter here.
    [[ ${macros[REMOTE]} ]] || macros[REMOTE]=$url
done < <(git remote -v)

# Loop through each line of our looksaide, and download the file:
# Regexes to determine which type of line it is and match the fields.
new_re='^([a-z]+[0-9]+) \(([^\)]+)\) = ([0-9a-f]+)$'
old_re='^([0-9a-f]+) ([^ ]+)$'
# Regex used for skipping lines with only whitespace.
skip_re='^[[:space:]]*$'
for line in "${sourcelines[@]}"; do
    macros[SHATYPE]=""
    shopt -s nocasematch
    if [[ $line =~ $new_re ]]; then
	# This is a new-style line: "SHATYPE (NAME) = HASH"
	macros[SHATYPE]=${BASH_REMATCH[1],,}
	macros[FILENAME]=${BASH_REMATCH[2]}
	macros[HASH]=${BASH_REMATCH[3]}
    elif [[ $line =~ $old_re ]]; then
	# This is an old-style line: "HASH NAME"
	macros[HASH]=${BASH_REMATCH[1]}
	macros[FILENAME]=${BASH_REMATCH[2]}
    elif [[ $line =~ $skip_re ]]; then
	# This line just has whitespace, skip it.
	continue
    else
	echo "ERROR: This lookaside line does not appear to have 2 or 4 space-separated fields.  I don't know how to parse this line:"
	printf '%s\n' "$line"
	exit 1
    fi
    shopt -u nocasematch
  
    # We have a hash and a filename, now we need to find the hash type (based on string length):
    # UPDATE: We don't need to do this if we already have it from the line.
    if [[ ! ${macros[SHATYPE]} ]]; then
	macros[SHATYPE]=$(hashtype "${macros[HASH]}")
    fi

    # Finally, we have all our information call the download function with the relevant variables:
    download
done
