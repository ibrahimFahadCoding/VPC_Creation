#
# Copyright 2007 Google LLC. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# WARNING: This file is externally viewable by our users.  All comments from
# this file will be stripped.  The docstrings will NOT.  Do not put sensitive
# information in docstrings.  If you must communicate internal information in
# this source file, please place them in comments only.


from __future__ import absolute_import
from googlecloudsdk.appengine.api import validation
from googlecloudsdk.appengine.api import yaml_builder
from googlecloudsdk.appengine.api import yaml_errors
from googlecloudsdk.appengine.api import yaml_listener
from ruamel import yaml


class _ObjectMapper(object):
  """Wrapper used for mapping attributes from a yaml file to an object.

  This wrapper is required because objects do not know what property they are
  associated with a creation time, and therefore can not be instantiated
  with the correct class until they are mapped to their parents.
  """

  def __init__(self):
    """Object mapper starts off with empty value."""
    self.value = None
    self.seen = set()

  def set_value(self, value):
    """Set value of instance to map to.

    Args:
      value: Instance that this mapper maps to.
    """
    self.value = value

  def see(self, key):
    if key in self.seen:
      raise yaml_errors.DuplicateAttribute("Duplicate attribute '%s'." % key)
    self.seen.add(key)


class _ObjectSequencer(object):
  """Wrapper used for building sequences from a yaml file to a list.

  This wrapper is required because objects do not know what property they are
  associated with a creation time, and therefore can not be instantiated
  with the correct class until they are mapped to their parents.
  """

  def __init__(self):
    """Object sequencer starts off with empty value."""
    self.value = []
    self.constructor = None

  def set_constructor(self, constructor):
    """Set object used for constructing new sequence instances.

    Args:
      constructor: Callable which can accept no arguments.  Must return
        an instance of the appropriate class for the container.
    """
    self.constructor = constructor


class ObjectBuilder(yaml_builder.Builder):
  """Builder used for constructing validated objects.

  Given a class that implements validation.ValidatedBase, it will parse a YAML
  document and attempt to build an instance of the class.
  ObjectBuilder will only map YAML fields that are accepted by the
  ValidatedBase's GetValidator function.
  Lists are mapped to validated.  Repeated attributes and maps are mapped to
  validated.Type properties.

  For a YAML map to be compatible with a class, the class must have a
  constructor that can be called with no parameters.  If the provided type
  does not have such a constructor a parse time error will occur.
  """

  def __init__(self, default_class):
    """Initialize validated object builder.

    Args:
      default_class: Class that is instantiated upon the detection of a new
        document.  An instance of this class will act as the document itself.
    """
    self.default_class = default_class

  def _GetRepeated(self, attribute):
    """Get the ultimate type of a repeated validator.

    Looks for an instance of validation.Repeated, returning its constructor.

    Args:
      attribute: Repeated validator attribute to find type for.

    Returns:
      The expected class of of the Type validator, otherwise object.
    """
    if isinstance(attribute, validation.Optional):
      attribute = attribute.validator
    if isinstance(attribute, validation.Repeated):
      return attribute.constructor
    return object

  def BuildDocument(self):
    """Instantiate new root validated object.

    Returns:
      New instance of validated object.
    """
    return self.default_class()

  def BuildMapping(self, top_value):
    """New instance of object mapper for opening map scope.

    Args:
      top_value: Parent of nested object.

    Returns:
      New instance of object mapper.
    """
    result = _ObjectMapper()
    # The first map encountered must be mapped directly to the
    # main document instance.
    if isinstance(top_value, self.default_class):
      result.value = top_value
    return result

  def EndMapping(self, top_value, mapping):
    """When leaving scope, makes sure new object is initialized.

    This method is mainly for picking up on any missing required attributes.

    Args:
      top_value: Parent of closing mapping object.
      mapping: _ObjectMapper instance that is leaving scope.
    """
    # make sure that mapping.value is a non-built-in type (i.e. can have
    # 'CheckInitialized' called on it)
    if not hasattr(mapping.value, 'CheckInitialized'):
      raise validation.ValidationError('Cannot convert map to non-map value.')

    try:
      mapping.value.CheckInitialized()
    except validation.ValidationError:
      # These should just pass through.
      raise
    except Exception as e:
      # Some errors may have problematic encoding or other issues.
      # Re-raising an error in this block would be very hard to debug
      # for the time being so instead, on error, the value is merely
      # obscured.
      try:
        error_str = str(e)
      except Exception:
        error_str = '<unknown>'

      # Wrap in a ValidationError
      raise validation.ValidationError(error_str, e)

  def BuildSequence(self, top_value):
    """New instance of object sequence.

    Args:
      top_value: Object that contains the new sequence.

    Returns:
      A new _ObjectSequencer instance.
    """
    return _ObjectSequencer()

  def MapTo(self, subject, key, value):
    """Map key-value pair to an objects attribute.

    Args:
      subject: _ObjectMapper of object that will receive new attribute.
      key: Key of attribute.
      value: Value of new attribute.

    Raises:
      UnexpectedAttribute when the key is not a validated attribute of
      the subject value class.
    """
    assert isinstance(subject.value, validation.ValidatedBase)

    try:
      attribute = subject.value.GetValidator(key)
    except validation.ValidationError as err:
      raise yaml_errors.UnexpectedAttribute(err)

    if isinstance(value, _ObjectMapper):
      # Now know what class the new instance should be.
      # Time to construct it from the attributes expected type.
      value.set_value(attribute.expected_type())
      value = value.value
    elif isinstance(value, _ObjectSequencer):
      # Now know what class new instances within the sequence should be.
      value.set_constructor(self._GetRepeated(attribute))
      value = value.value

    subject.see(key)
    try:
      subject.value.Set(key, value)
    except validation.ValidationError as e:
      # Some errors may have problematic encoding or other issues.
      # Re-raising an error in this block would be very hard to debug
      # for the time being so instead, on error, the value is merely
      # obscured.
      try:
        error_str = str(e)
      except Exception:
        error_str = '<unknown>'

      try:
        value_str = str(value)
      except Exception:
        value_str = '<unknown>'

      # Update error message with a better message.
      e.message = ("Unable to assign value '%s' to attribute '%s':\n%s" %
                   (value_str, key, error_str))
      raise e
    except Exception as e:
      try:
        error_str = str(e)
      except Exception:
        error_str = '<unknown>'

      try:
        value_str = str(value)
      except Exception:
        value_str = '<unknown>'

      # Raise a more generic exception message.
      message = ("Unable to assign value '%s' to attribute '%s':\n%s" %
                 (value_str, key, error_str))
      raise validation.ValidationError(message, e)

  def AppendTo(self, subject, value):
    """Append a value to a sequence.

    Args:
      subject: _ObjectSequence that is receiving new value.
      value: Value that is being appended to sequence.
    """
    if isinstance(value, _ObjectMapper):
      # Construct a new instance of the list.
      value.set_value(subject.constructor())
      subject.value.append(value.value)
    else:
      # Append value to list.
      subject.value.append(value)


def BuildObjects(default_class, stream, loader=yaml.loader.SafeLoader):
  """Build objects from stream.

  Handles the basic case of loading all the objects from a stream.

  Args:
    default_class: Class that is instantiated upon the detection of a new
      document.  An instance of this class will act as the document itself.
    stream: String document or open file object to process as per the
      yaml.parse method.  Any object that implements a 'read()' method which
      returns a string document will work with the YAML parser.
    loader_class: Used for dependency injection.

  Returns:
    List of default_class instances parsed from the stream.
  """
  builder = ObjectBuilder(default_class)
  handler = yaml_builder.BuilderHandler(builder)
  listener = yaml_listener.EventListener(handler)

  listener.Parse(stream, loader, version=(1, 1))
  return handler.GetResults()


def BuildSingleObject(default_class, stream, loader=yaml.loader.SafeLoader):
  """Build object from stream.

  Handles the basic case of loading a single object from a stream.

  Args:
    default_class: Class that is instantiated upon the detection of a new
      document.  An instance of this class will act as the document itself.
    stream: String document or open file object to process as per the
      yaml.parse method.  Any object that implements a 'read()' method which
      returns a string document will work with the YAML parser.
    loader_class: Used for dependency injection.
  """
  definitions = BuildObjects(default_class, stream, loader)

  if len(definitions) < 1:
    raise yaml_errors.EmptyConfigurationFile()
  if len(definitions) > 1:
    raise yaml_errors.MultipleConfigurationFile()
  return definitions[0]
