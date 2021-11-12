#!/usr/bin/env python3
"""
    unwebpack_sourcemap.py
    by rarecoil (github.com/rarecoil/unwebpack-sourcemap)

    Reads Webpack source maps and extracts the disclosed
    uncompiled/commented source code for review. Can detect and
    attempt to read sourcemaps from Webpack bundles with the `-d`
    flag. Puts source into a directory structure similar to dev.
"""

import argparse
import json
import os
import re
import string
import sys
from urllib.parse import urlparse
from unicodedata import normalize

import requests
from bs4 import BeautifulSoup, SoupStrainer


class SourceMapExtractor(object):
    """Primary SourceMapExtractor class. Feed this arguments."""

    _target = None
    _is_local = False
    _attempt_sourcemap_detection = False
    _output_directory = ""
    _target_extracted_sourcemaps = []

    _path_sanitiser = None


    def __init__(self, options):
        """Initialize the class."""
        if 'output_directory' not in options:
            raise SourceMapExtractorError("output_directory must be set in options.")
        else:
            self._output_directory = os.path.abspath(options['output_directory'])
            if not os.path.isdir(self._output_directory):
                if options['make_directory'] is True:
                    os.mkdir(self._output_directory)
                else:
                    raise SourceMapExtractorError("output_directory does not exist. Pass --make-directory to auto-make it.")

        self._path_sanitiser = PathSanitiser(self._output_directory)

        if options['disable_ssl_verification'] == True:
            self.disable_verify_ssl = True
        else:
            self.disable_verify_ssl = False
          
        if options['local'] == True:
            self._is_local = True

        if options['detect'] == True:
            self._attempt_sourcemap_detection = True

        self._validate_target(options['uri_or_file'])


    def run(self):
        """Run extraction process."""
        if self._is_local == False:
            if self._attempt_sourcemap_detection:
                detected_sourcemaps = self._detect_js_sourcemaps(self._target)
                for sourcemap in detected_sourcemaps:
                    self._parse_remote_sourcemap(sourcemap)
            else:
                self._parse_remote_sourcemap(self._target)

        else:
            self._parse_sourcemap(self._target)


    def _validate_target(self, target):
        """Do some basic validation on the target."""
        parsed = urlparse(target)
        if self._is_local is True:
            self._target = os.path.abspath(target)
            if not os.path.isfile(self._target):
                raise SourceMapExtractorError("uri_or_file is set to be a file, but doesn't seem to exist. check your path.")
        else:
            if parsed.scheme == "":
                raise SourceMapExtractorError("uri_or_file isn't a URI, and --local was not set. set --local?")
            file, ext = os.path.splitext(parsed.path)
            self._target = target
            if ext != '.map' and self._attempt_sourcemap_detection is False:
                print("WARNING: URI does not have .map extension, and --detect is not flagged.")


    def _parse_remote_sourcemap(self, uri):
        """GET a remote sourcemap and parse it."""
        data, final_uri = self._get_remote_data(uri)
        if data is not None:
            self._parse_sourcemap(data, True)
        else:
            print("WARNING: Could not retrieve sourcemap from URI %s" % final_uri)


    def _detect_js_sourcemaps(self, uri):
        """Pull HTML and attempt to find JS files, then read the JS files and look for sourceMappingURL."""
        remote_sourcemaps = []
        data, final_uri = self._get_remote_data(uri)

        # TODO: scan to see if this is a sourcemap instead of assuming HTML
        print("Detecting sourcemaps in HTML at %s" % final_uri)
        script_strainer = SoupStrainer("script", src=True)
        try:
            soup = BeautifulSoup(data, "html.parser", parse_only=script_strainer)
        except:
            raise SourceMapExtractorError("Could not parse HTML at URI %s" % final_uri)

        for script in soup:
            source = script['src']
            parsed_uri = urlparse(source)
            next_target_uri = ""
            if parsed_uri.scheme != '':
                next_target_uri = source
            else:
                current_uri = urlparse(final_uri)
                built_uri = current_uri.scheme + "://" + current_uri.netloc + source
                next_target_uri = built_uri

            js_data, last_target_uri = self._get_remote_data(next_target_uri)
            # get last line of file
            last_line = js_data.rstrip().split("\n")[-1]
            regex = "\\/\\/#\s*sourceMappingURL=(.*)$"
            matches = re.search(regex, last_line)
            if matches:
                asset = matches.groups(0)[0].strip()
                asset_target = urlparse(asset)
                if asset_target.scheme != '':
                    print("Detected sourcemap at remote location %s" % asset)
                    remote_sourcemaps.append(asset)
                else:
                    current_uri = urlparse(last_target_uri)
                    asset_uri = current_uri.scheme + '://' + \
                        current_uri.netloc + \
                        os.path.dirname(current_uri.path) + \
                        '/' + asset
                    print("Detected sourcemap at remote location %s" % asset_uri)
                    remote_sourcemaps.append(asset_uri)

        return remote_sourcemaps


    def _parse_sourcemap(self, target, is_str=False):
        map_data = ""
        if is_str is False:
            if os.path.isfile(target):
                with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                    map_data = f.read()
        else:
            map_data = target

        # with the sourcemap data, pull directory structures
        try:
            map_object = json.loads(map_data)
        except json.JSONDecodeError:
            print("ERROR: Failed to parse sourcemap %s. Are you sure this is a sourcemap?" % target)
            return False

        # we need `sourcesContent` and `sources`.
        # do a basic validation check to make sure these exist and agree.
        if 'sources' not in map_object or 'sourcesContent' not in map_object:
            print("ERROR: Sourcemap does not contain sources and/or sourcesContent, cannot extract.")
            return False

        if len(map_object['sources']) != len(map_object['sourcesContent']):
            print("WARNING: sources != sourcesContent, filenames may not match content")

        for source, content in zip(map_object['sources'], map_object['sourcesContent']):
            # remove webpack:// from paths
            # and do some checks on it
            write_path = self._get_sanitised_file_path(source)
            if write_path is None:
                print("ERROR: Could not sanitize path %s" % source)
                continue

            os.makedirs(os.path.dirname(write_path), mode=0o755, exist_ok=True)
            with open(write_path, 'w', encoding='utf-8', errors='ignore', newline='') as f:
                print("Writing %s..." % os.path.basename(write_path))
                f.write(content)

    def _get_sanitised_file_path(self, sourcePath):
        """Sanitise webpack paths for separators/relative paths"""
        sourcePath = sourcePath.replace("webpack:///", "")
        exts = sourcePath.split(" ")

        if exts[0] == "external":
            print("WARNING: Found external sourcemap %s, not currently supported. Skipping" % exts[1])
            return None

        path, filename = os.path.split(sourcePath)
        if path[:2] == './':
            path = path[2:]
        if path[:3] == '../':
            path = 'parent_dir/' + path[3:]
        if path[:1] == '.':
            path = ""

        filepath = self._path_sanitiser.make_valid_file_path(path, filename)
        return filepath

    def _get_remote_data(self, uri):
        """Get remote data via http."""

        if self.disable_verify_ssl == True:
            result = requests.get(uri, verify=False)
        else:
            result = requests.get(uri)

        # Redirect
        if not uri == result.url:
            return self._get_remote_data(result.url)

        if result.status_code == 200:
            return result.text, result.url
        else:
            print("WARNING: Got status code %d for URI %s" % (result.status_code, result.url))
            return None, result.url


class PathSanitiser(object):
    """https://stackoverflow.com/questions/13939120/sanitizing-a-file-path-in-python"""

    EMPTY_NAME = "empty"

    empty_idx = 0
    root_path = ""

    def __init__(self, root_path):
        self.root_path = root_path

    def ensure_directory_exists(self, path_directory):
        if not os.path.exists(path_directory):
            os.makedirs(path_directory)

    def os_path_separators(self):
        seps = []
        for sep in os.path.sep, os.path.altsep:
            if sep:
                seps.append(sep)
        return seps

    def sanitise_filesystem_name(self, potential_file_path_name):
        # Sort out unicode characters
        valid_filename = normalize('NFKD', potential_file_path_name).encode('ascii', 'ignore').decode('ascii')
        # Replace path separators with underscores
        for sep in self.os_path_separators():
            valid_filename = valid_filename.replace(sep, '_')
        # Ensure only valid characters
        valid_chars = "-_.() {0}{1}".format(string.ascii_letters, string.digits)
        valid_filename = "".join(ch for ch in valid_filename if ch in valid_chars)
        # Ensure at least one letter or number to ignore names such as '..'
        valid_chars = "{0}{1}".format(string.ascii_letters, string.digits)
        test_filename = "".join(ch for ch in potential_file_path_name if ch in valid_chars)
        if len(test_filename) == 0:
            # Replace empty file name or file path part with the following
            valid_filename = self.EMPTY_NAME + '_' + str(self.empty_idx)
            self.empty_idx += 1
        return valid_filename

    def get_root_path(self):
        # Replace with your own root file path, e.g. '/place/to/save/files/'
        filepath = self.root_path
        filepath = os.path.abspath(filepath)
        # ensure trailing path separator (/)
        if not any(filepath[-1] == sep for sep in self.os_path_separators()):
            filepath = '{0}{1}'.format(filepath, os.path.sep)
        self.ensure_directory_exists(filepath)
        return filepath

    def path_split_into_list(self, path):
        # Gets all parts of the path as a list, excluding path separators
        parts = []
        while True:
            newpath, tail = os.path.split(path)
            if newpath == path:
                assert not tail
                if path and path not in self.os_path_separators():
                    parts.append(path)
                break
            if tail and tail not in self.os_path_separators():
                parts.append(tail)
            path = newpath
        parts.reverse()
        return parts

    def sanitise_filesystem_path(self, potential_file_path):
        # Splits up a path and sanitises the name of each part separately
        path_parts_list = self.path_split_into_list(potential_file_path)
        sanitised_path = ''
        for path_component in path_parts_list:
            sanitised_path = '{0}{1}{2}'.format(sanitised_path,
                self.sanitise_filesystem_name(path_component),
                os.path.sep)
        return sanitised_path

    def check_if_path_is_under(self, parent_path, child_path):
        # Using the function to split paths into lists of component parts, check that one path is underneath another
        child_parts = self.path_split_into_list(child_path)
        parent_parts = self.path_split_into_list(parent_path)
        if len(parent_parts) > len(child_parts):
            return False
        return all(part1==part2 for part1, part2 in zip(child_parts, parent_parts))

    def make_valid_file_path(self, path=None, filename=None):
        root_path = self.get_root_path()
        if path:
            sanitised_path = self.sanitise_filesystem_path(path)
            if filename:
                sanitised_filename = self.sanitise_filesystem_name(filename)
                complete_path = os.path.join(root_path, sanitised_path, sanitised_filename)
            else:
                complete_path = os.path.join(root_path, sanitised_path)
        else:
            if filename:
                sanitised_filename = self.sanitise_filesystem_name(filename)
                complete_path = os.path.join(root_path, sanitised_filename)
            else:
                complete_path = complete_path
        complete_path = os.path.abspath(complete_path)
        if self.check_if_path_is_under(root_path, complete_path):
            return complete_path
        else:
            return None

class SourceMapExtractorError(Exception):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A tool to extract code from Webpack sourcemaps. Turns black boxes into gray ones.")
    parser.add_argument("-l", "--local", action="store_true", default=False)
    parser.add_argument("-d", "--detect", action="store_true", default=False,
        help="Attempt to detect sourcemaps from JS assets in retrieved HTML.")
    parser.add_argument("--make-directory", action="store_true", default=False,
        help="Make the output directory if it doesn't exist.")
    parser.add_argument("--dangerously-write-paths", action="store_true", default=False,
        help="Write full paths. WARNING: Be careful here, you are pulling directories from an untrusted source.")
    parser.add_argument("--disable-ssl-verification", action="store_true", default=False,
         help="The script will not verify the site's SSL certificate.")

    parser.add_argument("uri_or_file", help="The target URI or file.")
    parser.add_argument("output_directory", help="Directory to output from sourcemap to.")

    if (len(sys.argv) < 3):
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    extractor = SourceMapExtractor(vars(args))
    extractor.run()
