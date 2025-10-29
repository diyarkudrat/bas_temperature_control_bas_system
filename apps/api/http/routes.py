"""API route handlers for BAS server"""

from __future__ import annotations

from typing import Any, Dict, Tuple
from flask import jsonify, request, render_template, g
import time

from app_platform.errors.api import make_error


def dashboard() -> str:
    return render_template('dashboard.html')


def auth_login_page() -> str:
    return render_template('auth/login.html')


def health(auth_config, firestore_factory) -> Tuple[Any, int]:
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
            health_status["firestore"] = {"status": "error", "detail": str(e)}

    response = jsonify(health_status)
    response.headers['Cache-Control'] = 'public, max-age=2'
    return response, 200


def receive_sensor_data(controller, firestore_factory) -> Tuple[Any, int]:
    try:
        data = request.get_json()
        if not data:
            return make_error("No data received", "MISSING_FIELDS")

        # Minimal logging for hot path
        controller.update_control(
            data.get('temp_tenths', 0),
            data.get('sensor_ok', False),
        )

        telemetry_data = {
            'timestamp': data.get('timestamp', time.time() * 1000),
            'temp_tenths': data.get('temp_tenths', 0),
            'sensor_ok': data.get('sensor_ok', False),
            'setpoint_tenths': controller.setpoint_tenths,
            'deadband_tenths': controller.deadband_tenths,
            'cool_active': controller.cool_active,
            'heat_active': controller.heat_active,
            'state': controller.state,
        }

        if firestore_factory and firestore_factory.is_telemetry_enabled():
            try:
                tenant_id = getattr(g, 'tenant_id', 'default')
                device_id = data.get('device_id', 'unknown')
                telemetry_service = firestore_factory.get_telemetry_service()
                telemetry_service.add_telemetry(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    data=telemetry_data,
                )
            except Exception as e:
                # downgrade to debug info; avoid noisy logs
                pass

        commands = controller.get_control_commands()
        return jsonify(commands), 200
    except Exception as e:
        return make_error("Internal server error", "INTERNAL_ERROR")


def get_status(controller) -> Tuple[Any, int]:
    return jsonify({
        "temp_tenths": controller.current_temp_tenths,
        "setpoint_tenths": controller.setpoint_tenths,
        "deadband_tenths": controller.deadband_tenths,
        "state": controller.state,
        "cool_active": controller.cool_active,
        "heat_active": controller.heat_active,
        "sensor_ok": controller.sensor_ok,
        "timestamp": time.time() * 1000,
    }), 200


def set_setpoint(controller) -> Tuple[Any, int]:
    try:
        data = request.get_json() or {}
        setpoint = data.get('setpoint_tenths')
        deadband = data.get('deadband_tenths')

        if setpoint is not None and not controller.set_setpoint(setpoint):
            return make_error("Invalid setpoint", "INVALID_ARGUMENT")

        if deadband is not None and not controller.set_deadband(deadband):
            return make_error("Invalid deadband", "INVALID_ARGUMENT")

        return jsonify({
            "success": True,
            "setpoint_tenths": controller.setpoint_tenths,
            "deadband_tenths": controller.deadband_tenths,
        }), 200
    except Exception:
        return make_error("Internal server error", "INTERNAL_ERROR")


def get_telemetry(firestore_factory) -> Tuple[Any, int]:
    try:
        limit = request.args.get('limit', 100, type=int)
        device_id = request.args.get('device_id', 'unknown')
        data = []
        if firestore_factory and firestore_factory.is_telemetry_enabled():
            try:
                tenant_id = getattr(g, 'tenant_id', 'default')
                telemetry_service = firestore_factory.get_telemetry_service()
                data = telemetry_service.query_recent(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    limit=limit,
                )
            except Exception:
                data = []
        return jsonify(data), 200
    except Exception:
        return make_error("Internal server error", "INTERNAL_ERROR")


def get_config(controller) -> Tuple[Any, int]:
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
        payload = {
            "provider": getattr(getattr(provider, "__class__", None), "__name__", "unknown"),
            "status": "error",
            "detail": str(e),
            "now_epoch_ms": int(time.time() * 1000),
        }

    response = jsonify(payload)
    response.headers['Cache-Control'] = 'public, max-age=2'
    return response, 200


