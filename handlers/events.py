"""Підготовка подій Windows та розбір їхнього часу."""

from argparse import Namespace
from email.policy import default
import uuid
from datetime import datetime, timezone

ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

def config_handler(channel, provider, config, event_id) -> dict:
    for source in config["sources"]:
        if source["channel"] == channel and source["provider"] == provider:
            categiries = source.get("event_categories", {})

            return {
                **source,
                "category": categiries.get(str(event_id))
            }

    defaults = config["defaults"]["windows_event_log"]

    return {
        ** defaults,
        "channel" : channel,
        "provider" : provider,
        "category" : None
    }

def process_events(xml, config, ns=ns):
    events_results = []

    for event in xml:
        record_id = str(uuid.uuid4())

        native_record_id = event.findtext(
            "ns:System/ns:EventRecordID",
            default=None,
            namespaces=ns
        )

        if native_record_id is not None:
            native_record_id = native_record_id.strip() or None

        channel = event.findtext('ns:System/ns:Channel', default="Unknown", namespaces=ns,)
        provider_element = event.find('ns:System/ns:Provider', namespaces=ns,)

        if provider_element is not None:
            provider = provider_element.get("Name", "Unknown")
        else:
            provider = "Unknown"

        event_id = event.findtext('ns:System/ns:EventID', default="Unknown", namespaces=ns,)
        source_description = config_handler(channel, provider, config, event_id)


        computer = event.findtext('ns:System/ns:Computer', default="Unknown", namespaces=ns,)
        time_created = event.find('ns:System/ns:TimeCreated', namespaces=ns)

        if time_created is not None:
            system_time = time_created.get('SystemTime', "Unknown")
        else:
            system_time = "Unknown"

        data_fields = event.findall('ns:EventData/ns:Data', namespaces=ns)

        attributes = {}
        for data in data_fields:
            name = data.get('Name', "Unknown")
            value = data.text if data.text is not None else ""
            attributes[name] = value

        events_results.append({
            "record_id": record_id,
            "native_record_id": native_record_id,
            "event_id": event_id,
            "computer": computer,
            "system_time": system_time,
            "data_fields": attributes,
            "channel" : channel,
            "provider" : provider,
            "source" : source_description
        })

    return events_results

def parse_event_time(value):
    if not isinstance(value, str):
        return None
    value = value.strip()

    if value is None or value == "" or value == "Unknown":
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None
    else:
        return parsed.astimezone(timezone.utc)
