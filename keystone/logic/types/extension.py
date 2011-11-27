class Extensions(object):
    """An extensions type to hold static extensions content."""

    def __init__(self, json_content, xml_content):
        self.xml_content = xml_content
        self.json_content = json_content

    def to_json(self):
        return self.json_content

    def to_xml(self):
        return self.xml_content
