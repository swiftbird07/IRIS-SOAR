Contributing
============

Contributing, wheither it be code, documentation, or bug reports, is very much appreciated.
The following document will help you get started with contributing to the project.

Contributing Code
-----------------

Before contributing make sure that the feature you want to add is not already 'in progress' on the GitHub projects page. If you are contributing in relation to an open issue or feature request, please state so in the pull request. You can contribute code by forking the project on GitHub and sending a pull request. Please make sure that you use the same coding style as the rest of the project. This means that you should use the same indentation, and the same variable names. If you are unsure about the coding style, please look at the existing code..
Please test your code using 'pytest' before sending a pull request. First use the existing 'test_integration_full.py' test at the 'tests' directory for a full integration test. Also use the relevant core/module test in the respective sub-directory when editig an existing module or core IRIS-SOAR funtionality. Please provide new appropiate unit tests if you are contributing any new integration.

Below I will specify on how to contribute a new integration or playbook:

New Integration
~~~~~~~~~~~~~~~

Any integration MUST provide a config file in the 'configs' directory. This config file MUST be named 'integration_name.yml' and MUST contain the following fields:

.. code:: yaml
    name: The name of the integration
    author: The author of the integration
    description: A short description of the integration
    version: The version of the integration
    provides_new_detections: If the integration provides new detections, this field MUST be set to 'True'. If the integration does not provide new detections, this field MUST be set to 'False'.
    provides_context: If the integration provides context, this field MUST be set to 'True'. If the integration does not provide context, this field MUST be set to 'False'.
    expects_result: If the integration expects a final result (true-positive/false-positive/unsure) from IRIS-SOAR, this field MUST be set to 'True'. If the integration does not expect a result, this field MUST be set to 'False'.



Besides these config parameters, the integration can make use of any additional defined configs.

The integration itself must then be placed in the 'integrations' directory. The integration MUST be named 'integration_name.py' and MUST contain the respective functions if it is enabled in the above section:

.. code:: python
    def provide_detections():
    """" This function returns the new detections.
    Args:
        None

    Returns:
        A list of detections. Each detection has to be a valid object of type 'Detection'.

    Raises:
        None
    """""


.. code:: python
    def provide_context(DetectionReport):
    """" This function returns context of a given detection report.

    Args:
        DetectionReport: A valid object of type 'DetectionReport'.

    Returns:
        The enriched DetectionReport object.
    """

.. code:: python
    def receive_result(Detection):
    """" This function receives a result to a detection from IRIS-SOAR.

    Args:
        Detection: A valid object of type 'Detection'.

    Returns:
        True if the result was successfully received, False otherwise.

    """




New Playbook
~~~~~~~~~~~~

A playbook MUST implement a function called 'check_applicable' which returns a boolean value. This function MUST check if the playbook is applicable to the given detection report. If the playbook is applicable, the function MUST return 'True'. If the playbook is not applicable, the function MUST return 'False'.

A playbook MUST implement a function called 'execute' which returns a boolean value. This function MUST execute the playbook on the given detection report. The updated detection report must be returned.

.. code:: python
    def check_applicable(DetectionReport):
    """" This function checks if the playbook is applicable to the given detection report.

    Args:
        DetectionReport: A valid object of type 'DetectionReport'.

    Returns:
        True if the playbook is applicable, False otherwise.

    """"

.. code:: python
    def execute(DetectionReport):
    """" This function executes the playbook on the given detection report.

    Args:
        DetectionReport: A valid object of type 'DetectionReport'.

    Returns:
        The updated DetectionReport object.

    """"

New Core Functionality
~~~~~~~~~~~~~~~~~~~~~~

If you want to contribute new core functionality, please make sure that you provide a unit test for the new functionality. The unit test MUST be placed in the 'tests' directory. The unit test MUST be named 'test_functionality_name.py' and MUST contain the following functions:

.. code:: python
    def test_functionality_name():
    """" This function tests the new functionality.

    Args:
        None

    Returns:
        None
    Raises:
        AssertionError: If the test fails.
    """"

Contributing Documentation
--------------------------

Documentation is very important for the project. If you find any errors in the documentation, please feel free to fix them. If you want to contribute to the documentation, please make sure that you use the same style as the rest of the documentation. This means that you should use the same indentation, and the same variable names. If you are unsure about the documentation style, please look at the existing documentation.

Contributing Bug Reports
------------------------

If you find any bugs, please report them on the GitHub issues page. Please make sure that you provide as much information as possible. This includes the following:

- The version of IRIS-SOAR you are using.
- The version of Python you are using.
- The version of the integration you are using (if applicable).
- The version of the playbook you are using (if applicable).
- How to reproduce the bug.
- The expected result.
- The actual result.

Contributing Feature Requests
-----------------------------

If you have any feature requests, please report them on the GitHub issues page. Please make sure that you provide as much information as possible. This includes the following:

- The feature you want to see implemented.
- Why you want to see this feature implemented.
- How you would like to see this feature implemented.
- Any other information that you think is relevant.


