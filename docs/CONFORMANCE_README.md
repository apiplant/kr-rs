## How to run

From the repo root, using the tools/test/conformance.sh script and the krc-claude container from this session:
```fish
# Start a full run (restarts kr in the container first)
KR_TEST_CONTAINER=krc-claude tools/test/conformance.sh run full

# Sonobuoy's status
KR_TEST_CONTAINER=krc-claude tools/test/conformance.sh status

# Block until the run completes
KR_TEST_CONTAINER=krc-claude /usr/bin/timeout 14000 tools/test/conformance.sh wait

# Retrieve the results into a directory and print a failure summary
KR_TEST_CONTAINER=krc-claude tools/test/conformance.sh results /tmp/round9
```

Failed test names land in /tmp/round9/failed-tests.txt, and the full log is /tmp/round9/plugins/e2e/results/global/e2e.log.

The Sonobuoy progress counter stays at 0 with kr, so for a live view, count passes and failures from the e2e log on disk:

```fish
docker exec krc-claude sh -c 'f=$(ls -t /store/pods/*/e2e.log | head -1); echo done=$(grep -ac "^------------------------------" $f) failed=$(grep -ac "^• \[FAILED\]" $f); tail -3 $f'
```

A full run takes about 45 minutes and needs a few GB of free memory. The last attempt was killed while your model server held about 50 GB, so check free -g first.
