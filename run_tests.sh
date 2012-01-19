#!/bin/bash

set -eu

function usage {
  echo "Usage: $0 [OPTION]..."
  echo "Run Keystone's test suite(s)"
  echo ""
  echo "  -O, --only test_suite    Only run the specified test suite. Valid values are:"
  echo "                               UnitTests:    runs unit tests"
  echo "                               ClientTests:  runs tests that start and hit an HTTP[S] server"
  echo "                               SQLTest:      runs functional tests with SQLAlchemy backend"
  echo "                               SSLTest:      runs client tests with SSL configured"
  echo "                               LDAPTest:     runs functional tests with LDAP backend"
  echo "                               MemcacheTest: runs functional tests with memcached storing tokens"
  echo "                               ClientWithoutHPIDMTest: runs client tests with HP-IDM extension disabled"
  echo "                               Note: by default, run_tests will run all suites"
  echo "  -V, --virtual-env        Always use virtualenv.  Install automatically if not present"
  echo "  -N, --no-virtual-env     Don't use virtualenv.  Run tests in local environment"
  echo "  -x, --stop               Stop running tests after the first error or failure."
  echo "  -f, --force              Force a clean re-build of the virtual environment. Useful when dependencies have been added."
  echo "                             Note: you might need to 'sudo' this since it pip installs into the vitual environment"  
  echo "  -P, --skip-pep8          Just run tests; skip pep8 check"
  echo "  -p, --pep8               Just run pep8"
  echo "  -l, --pylint             Just run pylint"
  echo "  -j, --json               Just validate JSON"
  echo "  -c, --with-coverage      Generate coverage report"
  echo "  -h, --help               Print this usage message"
  echo "  --hide-elapsed           Don't print the elapsed time for each test along with slow test list"
  echo "  --verbose                Print additional logging"
  echo "  --debug                  Enable debug logging in Keystone instances"
  echo ""
  echo "Note: with no options specified, the script will try to run the tests in a virtual environment,"
  echo "      If no virtualenv is found, the script will ask if you would like to create one.  If you "
  echo "      prefer to run tests NOT in a virtual environment, simply pass the -N option."
  echo ""
  echo "Note: with no options specified, the script will run the pep8 check after completing the tests."
  echo "      If you prefer not to run pep8, simply pass the -P option."
  exit
}

only_run_flag=0
only_run=""
function process_option {
  if [ $only_run_flag -eq 1 ]; then
    only_run_flag=0
    only_run=$1
    return
  else
    case "$1" in
      -h|--help) usage;;
      -V|--virtual-env) always_venv=1; never_venv=0;;
      -N|--no-virtual-env) always_venv=0; never_venv=1;;
      -O|--only) only_run_flag=1;;
      -f|--force) force=1;;
      -P|--skip-pep8) skip_pep8=1;;
      -p|--pep8) just_pep8=1;;
      -l|--pylint) just_pylint=1;;
      -j|--json) just_json=1;;
      -c|--with-coverage) coverage=1;;
      -*) addlopts="$addlopts $1";;
      *) addlargs="$addlargs $1"
    esac
  fi
}

venv=.venv
with_venv=tools/with_venv.sh
always_venv=0
never_venv=0
force=0
addlargs=
addlopts=
wrapper=""
just_pep8=0
skip_pep8=0
just_pylint=0
just_json=0
coverage=0

for arg in "$@"; do
  process_option $arg
done

# If enabled, tell nose/unittest to collect coverage data
if [ $coverage -eq 1 ]; then
    addlopts="$addlopts --with-coverage --cover-package=keystone"
fi

if [ "x$only_run" = "x" ]; then
    RUNTESTS="python run_tests.py$addlopts$addlargs"
else
    RUNTESTS="python run_tests.py$addlopts$addlargs -O $only_run"
fi

if [ $never_venv -eq 0 ]
then
  # Remove the virtual environment if --force used
  if [ $force -eq 1 ]; then
    echo "Cleaning virtualenv..."
    rm -rf ${venv}
  fi
  if [ -e ${venv} ]; then
    wrapper="${with_venv}"
  else
    if [ $always_venv -eq 1 ]; then
      # Automatically install the virtualenv
      python tools/install_venv.py
      wrapper="${with_venv}"
    else
      echo -e "No virtual environment found...create one? (Y/n) \c"
      read use_ve
      if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
        # Install the virtualenv and run the test suite in it
        python tools/install_venv.py
        wrapper=${with_venv}
      fi
    fi
  fi
fi

function run_tests {
  # Just run the test suites in current environment
  ${wrapper} $RUNTESTS 2> run_tests.log
  # If we get some short import error right away, print the error log directly
  RESULT=$?
  if [ "$RESULT" -ne "0" ];
  then
    ERRSIZE=`wc -l run_tests.log | awk '{print \$1}'`
    if [ "$ERRSIZE" -lt "40" ];
    then
        cat run_tests.log
    fi
  fi
  return $RESULT
}

function run_pep8 {
  echo "Running pep8 ..."
  # Opt-out files from pep8
  ignore_scripts="*.sh"
  ignore_files="*eventlet-patch,*pip-requires,*.log"
  ignore_dirs="*ajaxterm*"
  GLOBIGNORE="$ignore_scripts,$ignore_files,$ignore_dirs"
  srcfiles=`find bin -type f -not -name "*.log" -not -name "*.db"`
  srcfiles+=" keystone examples tools setup.py run_tests.py"
  # Just run PEP8 in current environment
  ${wrapper} pep8 --repeat --show-pep8 --show-source \
    --exclude=vcsversion.py,$GLOBIGNORE ${srcfiles}
}

function run_pylint {
  echo "Running pylint ..."
  PYLINT_OPTIONS="--rcfile=pylintrc --output-format=parseable"
  PYLINT_INCLUDE="keystone"
  echo "Pylint messages count: "
  pylint $PYLINT_OPTIONS $PYLINT_INCLUDE | grep 'keystone/' | wc -l
  echo "Run 'pylint $PYLINT_OPTIONS $PYLINT_INCLUDE' for a full report."
}

function validate_json {
  echo "Validating JSON..."
  python tools/validate_json.py
}


# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

if [ $just_pep8 -eq 1 ]; then
    run_pep8
    exit
fi

if [ $just_pylint -eq 1 ]; then
    run_pylint
    exit
fi

if [ $just_json -eq 1 ]; then
    validate_json
    exit
fi


run_tests
if [ $skip_pep8 -eq 0 ]; then
    # Run the pep8 check
    run_pep8
fi

# Since we run multiple test suites, we need to execute 'coverage combine'
if [ $coverage -eq 1 ]; then
    echo "Generating coverage report in covhtml/"
    ${wrapper} coverage combine
    ${wrapper} coverage html -d covhtml -i
    ${wrapper} coverage report --omit='/usr*,keystone/test*,.,setup.py,*egg*,/Library*,*.xml,*.tpl'
fi

