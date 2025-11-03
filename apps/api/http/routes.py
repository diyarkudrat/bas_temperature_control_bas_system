"""API route handlers for BAS server"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import time

from flask import jsonify, render_template, request

from logging_lib import get_logger as get_structured_logger
logger = get_structured_logger("api.http.routes")
sensor_logger = get_structured_logger("api.http.routes.sensor")
health_logger = get_structured_logger("api.http.routes.health")
controller_logger = get_structured_logger("api.http.routes.controller")

from app_platform.errors.api import make_error


def dashboard() -> str:
    return render_template('dashboard.html')


def auth_login_page() -> str:
    return render_template('auth/login.html')


def health(auth_config, firestore_factory) -> Tuple[Any, int]:
    """Check the health of the API."""

    health_status: Dict[str, Any] = {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {
            "auth": bool(auth_config is not None),
            "firestore": bool(firestore_factory is not None),
        },
    }

    if firestore_factory:
        try:
            firestore_health = firestore_factory.health_check()
            if isinstance(firestore_health, dict):
                # Minimal pass-through without repeated json validation
                health_status["firestore"] = firestore_health
            else:
                health_status["firestore"] = {"detail": str(firestore_health)}
        except Exception as e:
            health_logger.warning("Firestore health check failed", exc_info=True)
            health_status["firestore"] = {"status": "error", "detail": str(e)}

    health_logger.info(
        "Health endpoint reported",
        extra={
            "auth_enabled": health_status["services"]["auth"],
            "firestore_configured": health_status["services"]["firestore"],
        },
    )

    response = jsonify(health_status)
    response.headers['Cache-Control'] = 'public, max-age=2'

    return response, 200


def receive_sensor_data(controller, firestore_factory) -> Tuple[Any, int]:
    """Receive sensor data from the controller."""

    try:
        data = request.get_json()
        if not data:
            sensor_logger.warning("Sensor data missing payload")
            return make_error("No data received", "MISSING_FIELDS")

        sensor_logger.debug(
            "Sensor data received",
            extra={
                "has_temp": 'temp_tenths' in data,
                "has_state": 'sensor_ok' in data,
            },
        )

        controller.update_control(
            data.get('temp_tenths', 0),
            data.get('sensor_ok', False),
        )

        commands = controller.get_control_commands()

        return jsonify(commands), 200
    except Exception:
        sensor_logger.exception("Sensor data handling failed")
        return make_error("Internal server error", "INTERNAL_ERROR")


def get_status(controller) -> Tuple[Any, int]:
    """Get the status of the controller."""

    try:
        payload = {
            "temp_tenths": controller.current_temp_tenths,
            "setpoint_tenths": controller.setpoint_tenths,
            "deadband_tenths": controller.deadband_tenths,
            "state": controller.state,
            "cool_active": controller.cool_active,
            "heat_active": controller.heat_active,
            "sensor_ok": controller.sensor_ok,
            "timestamp": time.time() * 1000,
        }
        controller_logger.debug(
            "Controller status fetched",
            extra={
                "state": controller.state,
                "cool_active": controller.cool_active,
                "heat_active": controller.heat_active,
            },
        )

        return jsonify(payload), 200
    except Exception:
        controller_logger.exception("get_status failed")
        return make_error("Internal server error", "INTERNAL_ERROR")


def set_setpoint(controller) -> Tuple[Any, int]:
    """Set the setpoint and deadband of the controller."""

    try:
        data = request.get_json() or {}
        setpoint = data.get('setpoint_tenths')
        deadband = data.get('deadband_tenths')

        if setpoint is not None and not controller.set_setpoint(setpoint):
            controller_logger.warning("Invalid setpoint requested", extra={"setpoint": setpoint})
            return make_error("Invalid setpoint", "INVALID_ARGUMENT")

        if deadband is not None and not controller.set_deadband(deadband):
            controller_logger.warning("Invalid deadband requested", extra={"deadband": deadband})
            return make_error("Invalid deadband", "INVALID_ARGUMENT")

        controller_logger.info(
            "Controller setpoint updated",
            extra={
                "setpoint": controller.setpoint_tenths,
                "deadband": controller.deadband_tenths,
            },
        )
        return jsonify({
            "success": True,
            "setpoint_tenths": controller.setpoint_tenths,
            "deadband_tenths": controller.deadband_tenths,
        }), 200
    except Exception:
        controller_logger.exception("set_setpoint failed")
        return make_error("Internal server error", "INTERNAL_ERROR")


def get_config(controller) -> Tuple[Any, int]:
    """Get the configuration of the controller."""

    payload = {
        "setpoint_tenths": int(controller.setpoint_tenths),
        "deadband_tenths": int(controller.deadband_tenths),
        "min_on_time_ms": int(controller.min_on_time_ms),
        "min_off_time_ms": int(controller.min_off_time_ms),
    }
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=2'

    return response, 200



def auth_health(provider) -> Tuple[Any, int]:
    """Return authentication provider health info.

    Provider is injected by the server wiring. If not available, return a
    minimal, stable payload for observability without external I/O.
    """
    try:
        if provider is not None:
            payload = provider.healthcheck()
        else:
            payload = {
                "provider": "unavailable",
                "status": "init",
                "now_epoch_ms": int(time.time() * 1000),
                "mode": "unknown",
            }
    except Exception as e:
        health_logger.warning("Auth provider health check failed", exc_info=True)
        payload = {
            "provider": getattr(getattr(provider, "__class__", None), "__name__", "unknown"),
            "status": "error",
            "detail": str(e),
            "now_epoch_ms": int(time.time() * 1000),
        }

    health_logger.info(
        "Auth health endpoint reported",
        extra={"provider": payload.get("provider"), "status": payload.get("status")},
    )

    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=2'
    
    return response, 200


