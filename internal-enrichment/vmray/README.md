# OpenCTI VMRay Connector

This connector supports manual enrichment of observables using a sample as entry point.
* [VMRay](https://www.vmray.com/)

## Behavior

This connector is used as a manual enrichment connector. 

The process is as follows : 
* Retrieve the ES record of the corresponding sample (the one being enriched).
* Process the `summary_v2` in order to generate a bundle of STIX entities :
* Push the bundle back to openCTI
 
## Run the connector locally

Use the config file `config.yaml` to customize the configuration of the connector.
In order to run the connector locally, you need to port-forward the right resources. 

The connectors depend on the following : 
* OpenCti API
* ES
* RMQ

Once all the ports are correctly routed, you can run the main from the `src` folder.
```
python main.py
```

## Run the tests
To run the test, the packages in the file `tests/requirements-text.txt` must be installed on your machine.
You may need to declare the file `src/config.yaml`, use the file `src/config.yaml.sample` as a modal.
```
$ cd vmray/tests
$ pytest
```

### Run the connector against a given summary
If you need to test a given `summaryV2.json` using the connector, you may try the test file `tests/test_vmray.py` 

The procedure is as follows :
* In the `tests/resources/` folder, upload a custom summary file named `report_dict_custom.json`.
* Run the test using `pytest`
* The file `tests/resources/bundle.json` should be created by the connector with the corresping bundle


